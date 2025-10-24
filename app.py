#!/usr/bin/env python3
"""
GitLab-Jira Webhook Bot

This application receives GitLab pipeline webhooks and creates/updates Jira tickets
based on pipeline status and commit information. Uses JQL search with branch and repo
labels to track tickets across pipeline runs.

NOTE: All sensitive/project-specific information has been replaced with placeholders
for public sharing. Configuration should be done via environment variables.
"""

import os
import json
import logging
import hashlib
import asyncio
import hmac
from typing import Dict, Any, Optional
from datetime import datetime

import requests
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel

TICKET_CREATION_LOCKS = {}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="GitLab-Jira Webhook Bot",
    description="Bot that processes GitLab pipeline webhooks and updates Jira tickets",
    version="1.0.0"
)

# Configuration from environment variables
# PLACEHOLDER: Use a generic Atlassian URL as a default
JIRA_BASE_URL = os.getenv('JIRA_BASE_URL', 'https://your-domain.atlassian.net')
JIRA_API_TOKEN = os.getenv('JIRA_API_TOKEN')
JIRA_USER_EMAIL = os.getenv('JIRA_USER_EMAIL')
GITLAB_WEBHOOK_SECRET = os.getenv('GITLAB_WEBHOOK_SECRET')
# PLACEHOLDER: Use a generic GitLab URL as a default
GITLAB_BASE_URL = os.getenv('GITLAB_BASE_URL', 'https://gitlab.com')
GITLAB_API_TOKEN = os.getenv('GITLAB_API_TOKEN')

# Jira project configuration
# PLACEHOLDER: Use a generic project key
JIRA_PROJECT_KEY = os.getenv('JIRA_PROJECT_KEY', 'DEVOPSTASKS')
# PLACEHOLDER: Use a generic issue type ID
JIRA_ISSUE_TYPE_ID = os.getenv('JIRA_ISSUE_TYPE_ID', '10001')  # Generic Issue Type ID
# PLACEHOLDER: Use a generic transition ID
JIRA_CLOSE_TRANSITION_ID = os.getenv('JIRA_CLOSE_TRANSITION_ID', '31')  # Transition ID for 'Done' or 'Closed'

class GitLabWebhookPayload(BaseModel):
    """GitLab webhook payload structure for pipeline events"""
    object_kind: str
    object_attributes: Dict[str, Any]
    project: Dict[str, Any]
    commit: Optional[Dict[str, Any]] = None
    builds: Optional[list] = None

def verify_gitlab_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitLab webhook signature"""
    if not secret:
        logger.warning("No webhook secret configured, skipping signature verification")
        return True
    
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(f"sha256={expected_signature}", signature)

def get_jira_headers() -> Dict[str, str]:
    """Get headers for Jira API requests"""
    if not JIRA_API_TOKEN or not JIRA_USER_EMAIL:
        raise HTTPException(
            status_code=500,
            detail="Jira API credentials not configured"
        )
    
    return {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

def get_jira_auth():
    """Get authentication for Jira API requests"""
    if not JIRA_API_TOKEN or not JIRA_USER_EMAIL:
        raise HTTPException(
            status_code=500,
            detail="Jira API credentials not configured"
        )
    
    from requests.auth import HTTPBasicAuth
    return HTTPBasicAuth(JIRA_USER_EMAIL, JIRA_API_TOKEN)

def get_gitlab_headers() -> Dict[str, str]:
    """Get headers for GitLab API requests"""
    if not GITLAB_API_TOKEN:
        logger.warning("GitLab API token not configured, cannot fetch pipeline logs")
        return None
    
    return {
        'PRIVATE-TOKEN': GITLAB_API_TOKEN,
        'Content-Type': 'application/json'
    }

def clean_gitlab_logs(log_content: str) -> str:
    """Clean GitLab logs by removing ANSI escape codes and section markers"""
    import re
    
    # Remove ANSI escape codes (colors, formatting)
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    cleaned = ansi_escape.sub('', log_content)
    
    # Remove section markers like section_start and section_end
    # The pattern should be more flexible to handle variations in the tag content
    cleaned = re.sub(r'\u001b\[0Ksection_(start|end):\d+:[^\s]+\u001b\[0K', '', cleaned)
    cleaned = re.sub(r'section_(start|end):\d+:[^\s]+', '', cleaned)
    
    # Remove control characters and clean up whitespace
    cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', cleaned)
    
    # Clean up empty lines created by removal of markers/codes
    lines = [line.strip() for line in cleaned.split('\n')]
    lines = [line for line in lines if line] # Remove empty lines
    
    return '\n'.join(lines)

def get_failed_pipeline_logs(project_id: str, pipeline_id: str) -> Optional[str]:
    """Fetch the last 20 lines of logs from failed jobs in a pipeline"""
    try:
        if not GITLAB_API_TOKEN:
            logger.warning("GitLab API token not configured, skipping log fetch")
            return None
        
        # First, get all jobs for the pipeline
        jobs_url = f"{GITLAB_BASE_URL}/api/v4/projects/{project_id}/pipelines/{pipeline_id}/jobs"
        headers = get_gitlab_headers()
        
        jobs_response = requests.get(jobs_url, headers=headers, timeout=30)
        if jobs_response.status_code != 200:
            logger.error(f"Failed to fetch pipeline jobs: {jobs_response.status_code} - {jobs_response.text}")
            return None
        
        jobs = jobs_response.json()
        failed_jobs = [job for job in jobs if job.get('status') == 'failed']
        
        if not failed_jobs:
            logger.info("No failed jobs found in pipeline")
            return None
        
        # Get logs from the first failed job (usually the most relevant)
        failed_job = failed_jobs[0]
        job_id = failed_job.get('id')
        job_name = failed_job.get('name', 'Unknown Job')
        
        # Fetch the job trace/logs
        trace_url = f"{GITLAB_BASE_URL}/api/v4/projects/{project_id}/jobs/{job_id}/trace"
        trace_response = requests.get(trace_url, headers=headers, timeout=30)
        
        if trace_response.status_code != 200:
            logger.error(f"Failed to fetch job trace: {trace_response.status_code} - {trace_response.text}")
            return None
        
        # Clean the logs and get the last 20 lines
        log_content = trace_response.text
        cleaned_logs = clean_gitlab_logs(log_content)
        log_lines = cleaned_logs.split('\n')
        
        # Filter out completely empty lines after cleaning
        log_lines = [line for line in log_lines if line.strip()] 
        
        last_20_lines = log_lines[-20:]
        
        # Format the logs for display
        formatted_logs = '\n'.join(last_20_lines)
        
        logger.info(f"Successfully fetched and cleaned logs from failed job '{job_name}' (ID: {job_id})")
        # Use a simple text block for the logs within the description ADF
        return f"Failed Job: {job_name}\n\n{formatted_logs}"
        
    except Exception as e:
        logger.error(f"Error fetching pipeline logs: {str(e)}")
        return None

def find_open_ticket_by_branch(project_key: str, branch_name: str, repo_name: str) -> Optional[str]:
    """Search Jira for an open ticket matching the repository and branch name."""
    try:
        # Construct the JQL to search for the unique pattern: "Pipeline Failed" AND "repo_name/branch_name"
        jql_search_term = f'"{repo_name}/{branch_name}"'
        
        jql = (
            f'project = {project_key} AND '
            f'summary ~ "Pipeline Failed" AND '
            f'summary ~ {jql_search_term} AND '
            f'statusCategory IN ("To Do")'
        )
        
        query_params = {
            'jql': jql,
            'maxResults': 1,
            'fields': 'key'
        }
        
        response = requests.get(
            f"{JIRA_BASE_URL}/rest/api/3/search", 
            headers=get_jira_headers(),
            auth=get_jira_auth(),
            params=query_params,
            timeout=30
        )
        
        if response.status_code == 200:
            issues = response.json().get('issues', [])
            if issues:
                issue_key = issues[0]['key']
                logger.info(f"Found open ticket {issue_key} for branch {branch_name} in repo {repo_name}")
                return issue_key
        else:
            logger.error(f"JQL search failed: {response.status_code} - {response.text}")
        
        logger.info(f"No open ticket found for branch {branch_name} in project {repo_name}")
        return None
        
    except Exception as e:
        logger.error(f"Error searching for open ticket by branch: {str(e)}")
        return None

def create_jira_ticket(pipeline_data: Dict[str, Any], branch_name: str, repo_name: str) -> Optional[str]:
    """Create a new Jira ticket for the pipeline"""
    try:
        project = pipeline_data.get('project', {})
        commit = pipeline_data.get('commit', {})
        object_attrs = pipeline_data.get('object_attributes', {})
        
        # Extract relevant information
        project_name = project.get('name', 'Unknown Project')
        project_url = project.get('web_url', '')
        project_id = project.get('id', '')
        pipeline_id = object_attrs.get('id', 'Unknown')
        pipeline_status = object_attrs.get('status', 'unknown')
        commit_message = commit.get('message', 'No commit message') if commit else 'No commit message'
        commit_author_name = commit.get('author', {}).get('name', 'Unknown') if commit else 'Unknown'
        # commit_author_email is not used in description but is needed for watcher logic later
        pipeline_url = object_attrs.get('url', '')
        
        # Fetch pipeline logs if this is a failed pipeline
        pipeline_logs = None
        if pipeline_status == 'failed' and project_id:
            pipeline_logs = get_failed_pipeline_logs(str(project_id), str(pipeline_id))
        
        # Create ticket summary and description
        summary = f"Pipeline {pipeline_status.title()}: {project_name}/{branch_name} - {commit_message[:50]}"
        
        # Use ADF format for description with clickable links
        description_content = [
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": "Pipeline Information:\n- Status: ",
                        "marks": [{"type": "strong"}]
                    },
                    {
                        "type": "text",
                        "text": f"{pipeline_status.title()}\n- Pipeline ID: {pipeline_id}\n- Project: {project_name}\n- Branch: {branch_name}\n- Commit Author: {commit_author_name}\n- Commit Message: {commit_message}\n\nLinks:\n- Pipeline: "
                    },
                    {
                        "type": "text",
                        "text": "View Pipeline",
                        "marks": [
                            {
                                "type": "link",
                                "attrs": {
                                    "href": pipeline_url
                                }
                            }
                        ]
                    },
                    {
                        "type": "text",
                        "text": "\n- Project: "
                    },
                    {
                        "type": "text",
                        "text": "View Project",
                        "marks": [
                            {
                                "type": "link",
                                "attrs": {
                                    "href": project_url
                                }
                            }
                        ]
                    },
                    {
                        "type": "text",
                        "text": "\n\nDetails:\nThis ticket was automatically created from a GitLab pipeline webhook due to pipeline failure."
                    }
                ]
            }
        ]
        
        # Add pipeline logs if available
        if pipeline_logs:
            # Add a paragraph for the title
            description_content.append({
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": "\n\nPipeline Logs (Last 20 Lines):\n",
                        "marks": [{"type": "strong"}]
                    }
                ]
            })
            # Add the code block for the logs
            description_content.append({
                "type": "codeBlock",
                "attrs": {"language": "text"},
                "content": [
                    {
                        "type": "text",
                        "text": pipeline_logs
                    }
                ]
            })
        
        description = {
            "version": 1,
            "type": "doc",
            "content": description_content
        }
        
        # Prepare Jira issue data
        issue_data = {
            "fields": {
                "project": {"key": JIRA_PROJECT_KEY},
                "summary": summary,
                "description": description,
                "issuetype": {"id": JIRA_ISSUE_TYPE_ID},
                # PLACEHOLDER: Removed the hardcoded accountId. Assignee should be handled manually or via a known variable.
                # "assignee": {"accountId": "YOUR_JIRA_ACCOUNT_ID_HERE"} 
            }
        }
        
        # Create the ticket
        response = requests.post(
            f"{JIRA_BASE_URL}/rest/api/3/issue",
            headers=get_jira_headers(),
            auth=get_jira_auth(),
            json=issue_data,
            timeout=30
        )
        
        if response.status_code == 201:
            issue_key = response.json().get('key')
            logger.info(f"Created Jira ticket {issue_key} for pipeline {pipeline_id} (branch: {branch_name})")
            return issue_key
        else:
            logger.error(f"Failed to create Jira ticket: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"Error creating Jira ticket: {str(e)}")
        return None

def add_jira_watcher(issue_key: str, user_email: str) -> bool:
    """Add a user (by email) as a watcher to a Jira ticket.
       NOTE: Jira Cloud API requires the user's Account ID, not email, for watchers.
       We must search for the user by email first to get their Account ID.
    """
    try:
        # Step 1: Find the User's Account ID using the email
        search_params = {'query': user_email}
        search_response = requests.get(
            f"{JIRA_BASE_URL}/rest/api/3/user/search",
            headers=get_jira_headers(),
            auth=get_jira_auth(),
            params=search_params,
            timeout=10
        )
        
        if search_response.status_code != 200:
            logger.error(f"Failed to search user by email {user_email}: {search_response.status_code} - {search_response.text}")
            return False
            
        users = search_response.json()
        if not users:
            logger.warning(f"Commit author email {user_email} not found in Jira. Cannot add as watcher.")
            return False
            
        # Assuming the first result is the correct user
        account_id = users[0].get('accountId')

        if not account_id:
            logger.warning(f"Could not retrieve Account ID for email {user_email}.")
            return False

        # Step 2: Add the watcher using the Account ID
        watcher_url = f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}/watchers"
        
        # The watcher API expects the Account ID as the body, wrapped in quotes
        watcher_data = json.dumps(account_id)
        
        response = requests.post(
            watcher_url,
            headers={'Content-Type': 'application/json'},
            auth=get_jira_auth(),
            data=watcher_data,
            timeout=30
        )
        
        if response.status_code == 204: # 204 No Content is success for adding watcher
            logger.info(f"Successfully added {user_email} (ID: {account_id}) as watcher to {issue_key}")
            return True
        else:
            logger.error(f"Failed to add watcher to {issue_key}: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Error adding watcher: {str(e)}")
        return False

def update_jira_ticket(issue_key: str, pipeline_data: Dict[str, Any]) -> bool:
    """Update an existing Jira ticket with pipeline status"""
    try:
        object_attrs = pipeline_data.get('object_attributes', {})
        pipeline_status = object_attrs.get('status', 'unknown')
        pipeline_url = object_attrs.get('url', '')
        pipeline_id = object_attrs.get('id', 'Unknown')
        
        # Add comment about status change (using ADF format with clickable link)
        comment_data = {
            "body": {
                "version": 1,
                "type": "doc",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": f"Pipeline status updated to: ",
                                "marks": [{"type": "strong"}]
                            },
                            {
                                "type": "text",
                                "text": f"{pipeline_status.title()}\nPipeline ID: {pipeline_id}\nPipeline: "
                            },
                            {
                                "type": "text",
                                "text": "View Pipeline",
                                "marks": [
                                    {
                                        "type": "link",
                                        "attrs": {
                                            "href": pipeline_url
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        }
        
        # Add comment to the ticket
        response = requests.post(
            f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}/comment",
            headers=get_jira_headers(),
            auth=get_jira_auth(),
            json=comment_data,
            timeout=30
        )
        
        if response.status_code == 201:
            logger.info(f"Updated Jira ticket {issue_key} with status {pipeline_status}")
            return True
        else:
            logger.error(f"Failed to update Jira ticket {issue_key}: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Error updating Jira ticket {issue_key}: {str(e)}")
        return False

def transition_jira_ticket(issue_key: str, transition_id: str) -> bool:
    """Transition a Jira ticket to a different status"""
    try:
        transition_data = {
            "transition": {
                "id": transition_id
            }
        }
        
        response = requests.post(
            f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}/transitions",
            headers=get_jira_headers(),
            auth=get_jira_auth(),
            json=transition_data,
            timeout=30
        )
        
        if response.status_code == 204:
            logger.info(f"Successfully transitioned Jira ticket {issue_key} with transition {transition_id}")
            return True
        else:
            logger.error(f"Failed to transition Jira ticket {issue_key}: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Error transitioning Jira ticket {issue_key}: {str(e)}")
        return False

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/gitlab-pipeline")
async def handle_gitlab_webhook(
    request: Request,
    x_gitlab_token: Optional[str] = Header(None),
    x_gitlab_event: Optional[str] = Header(None)
):
    """Handle GitLab pipeline webhook"""
    try:
        # Get raw body for signature verification
        body = await request.body()
        
        # Verify webhook signature if secret is configured
        if GITLAB_WEBHOOK_SECRET and x_gitlab_token:
            if not verify_gitlab_signature(body, x_gitlab_token, GITLAB_WEBHOOK_SECRET):
                logger.warning("Invalid webhook signature")
                raise HTTPException(status_code=401, detail="Invalid signature")

        # Parse JSON payload
        try:
            payload = json.loads(body.decode('utf-8'))
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON payload: {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid JSON payload")
        
        # Validate payload structure
        if payload.get('object_kind') != 'pipeline':
            logger.info(f"Ignoring non-pipeline webhook: {payload.get('object_kind')}")
            return JSONResponse(content={"message": "Ignored non-pipeline event"})
        
        # Extract necessary variables
        object_attrs = payload.get('object_attributes', {})
        pipeline_status = object_attrs.get('status', 'unknown')
        pipeline_id = str(object_attrs.get('id', ''))
        branch_name = object_attrs.get('ref', 'unknown-ref')
        repo_name = (
            payload.get('project', {}).get('name') or 
            payload.get('project', {}).get('path') or 
            payload.get('project', {}).get('path_with_namespace', '').split('/')[-1] or
            'unknown-repo'
        )
        
        logger.info(f"Processing pipeline {pipeline_id} (branch: {branch_name}, repo: {repo_name}) with status {pipeline_status}")
        
        # Check if this is a status change we care about
        if pipeline_status not in ['running', 'success', 'failed', 'canceled']:
            logger.info(f"Ignoring pipeline status: {pipeline_status}")
            return JSONResponse(content={"message": f"Ignored status: {pipeline_status}"})

        # --- LOCKING SETUP ---
        lock_key = f"{repo_name}/{branch_name}" 
        
        if lock_key not in TICKET_CREATION_LOCKS:
            TICKET_CREATION_LOCKS[lock_key] = asyncio.Lock()
            
        lock = TICKET_CREATION_LOCKS[lock_key]
        # --- END LOCKING SETUP ---
        
        # --- FAILED STATUS HANDLER (INSIDE LOCK) ---
        if pipeline_status == 'failed':
            async with lock: # Forces only one request to run this block at a time
                
                # 1. Search for an existing OPEN ticket
                open_ticket_key = find_open_ticket_by_branch(JIRA_PROJECT_KEY, branch_name, repo_name)
                
                if open_ticket_key:
                    # Ticket already exists; update it.
                    update_jira_ticket(open_ticket_key, payload)
                    message = f"Added failure comment to existing ticket {open_ticket_key}"
                else:
                    # 2. No ticket found; create it.
                    ticket_key = create_jira_ticket(payload, branch_name, repo_name)
                    
                    if ticket_key:
                        message = f"Created new Jira ticket {ticket_key}"
                        
                        # Add watcher to the ticket
                        commit_author_email = payload.get('commit', {}).get('author', {}).get('email')
                        if commit_author_email:
                            # This needs to run *outside* the lock but *after* creation, which is fine as it's sequential.
                            add_jira_watcher(ticket_key, commit_author_email)
                        
                        # 3. Wait for Jira's index to refresh BEFORE releasing the lock.
                        logger.info(f"Ticket {ticket_key} created. Waiting 2 seconds for Jira index...")
                        await asyncio.sleep(2)
                    else:
                        raise HTTPException(status_code=500, detail="Failed to create Jira ticket")
            
            return JSONResponse(content={
                "message": message,
                "status": pipeline_status,
                "branch": branch_name,
                "repo": repo_name
            })
        
        elif pipeline_status == 'success':
            # Get open_ticket_key for success events
            open_ticket_key = find_open_ticket_by_branch(JIRA_PROJECT_KEY, branch_name, repo_name)
            if open_ticket_key:
                # Found an open ticket for this branch/repo: close it!
                update_jira_ticket(open_ticket_key, payload)  # Add 'success' comment
                transition_success = transition_jira_ticket(open_ticket_key, JIRA_CLOSE_TRANSITION_ID)
                
                if transition_success:
                    message = f"Successfully closed Jira ticket {open_ticket_key}"
                else:
                    message = f"Updated Jira ticket {open_ticket_key} but failed to close it"
                
                return JSONResponse(content={
                    "message": message,
                    "ticket_key": open_ticket_key,
                    "status": pipeline_status,
                    "branch": branch_name,
                    "repo": repo_name
                })
            else:
                logger.info(f"Success pipeline for {repo_name}/{branch_name} but no open ticket found. Ignoring.")
                return JSONResponse(content={
                    "message": "Success received, no open ticket found to close.",
                    "status": pipeline_status,
                    "branch": branch_name,
                    "repo": repo_name
                })
        
        elif pipeline_status in ['running', 'canceled']:
            # Search for an open ticket only to update it
            open_ticket_key = find_open_ticket_by_branch(JIRA_PROJECT_KEY, branch_name, repo_name)
            
            if open_ticket_key:
                # Update existing ticket with current status
                success = update_jira_ticket(open_ticket_key, payload)
                if success:
                    return JSONResponse(content={
                        "message": f"Updated existing Jira ticket for {pipeline_status} pipeline",
                        "ticket_key": open_ticket_key,
                        "status": pipeline_status,
                        "branch": branch_name,
                        "repo": repo_name
                    })
                else:
                    raise HTTPException(status_code=500, detail="Failed to update Jira ticket")
            else:
                logger.info(f"Pipeline {pipeline_id} is {pipeline_status} but no failure ticket exists for {repo_name}/{branch_name}")
                return JSONResponse(content={
                    "message": f"Pipeline is {pipeline_status} but no failure ticket exists",
                    "status": pipeline_status,
                    "branch": branch_name,
                    "repo": repo_name
                })
        
        else:
            return JSONResponse(content={
                "message": f"Unhandled pipeline status: {pipeline_status}",
                "status": pipeline_status,
                "branch": branch_name,
                "repo": repo_name
            })
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error processing webhook: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/")
async def root():
    """Root endpoint with basic information"""
    return {
        "service": "GitLab-Jira Webhook Bot",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "webhook": "/gitlab-pipeline"
        }
    }

if __name__ == "__main__":
    import uvicorn
    
    # Validate required configuration
    if not JIRA_API_TOKEN:
        logger.error("JIRA_API_TOKEN environment variable is required")
        exit(1)
    
    if not JIRA_USER_EMAIL:
        logger.error("JIRA_USER_EMAIL environment variable is required")
        exit(1)
    
    if not GITLAB_API_TOKEN:
        logger.warning("GITLAB_API_TOKEN environment variable not set. Pipeline logs will not be included in tickets.")
    
    logger.info("Starting GitLab-Jira Webhook Bot")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8080,
        log_level="info"
    )
