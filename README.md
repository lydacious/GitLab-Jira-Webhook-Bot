# 🤖 GitLab-Jira Webhook Bot

A simple, asynchronous Python bot built with **FastAPI** to automate the creation and closing of Jira tickets based on **GitLab Pipeline Webhooks**.

When a GitLab CI/CD pipeline fails, this bot automatically creates a dedicated Jira ticket for tracking. When the pipeline successfully runs again on the same branch, the existing ticket is updated and transitioned to a "Done" or "Closed" status.

## ✨ Features

* **Failure Ticket Creation:** Automatically creates a Jira issue upon a pipeline failure for a specific branch.
* **Failed Job Logs:** Fetches and includes the **last 20 lines of the failed job's log** directly in the Jira ticket description for immediate debugging.
* **Automatic Watchers:** Automatically adds the **commit author** (via their email) as a watcher to the newly created Jira ticket.
* **Ticket Tracking:** Uses JQL to search for existing open tickets based on the **repository name** and **branch name** to prevent duplicate tickets.
* **Status Updates:** Adds comments to the existing Jira ticket for subsequent pipeline runs (e.g., `running`, `canceled`, `failed`).
* **Automatic Closure:** Transitions the open ticket to a "Done" status upon a pipeline `success` event for that branch.
* **Webhook Security:** Verifies GitLab's `X-Gitlab-Token` signature using `HMAC-SHA256` for security (if a secret is configured).

## ⚙️ Configuration

The bot is configured entirely using **environment variables**.

| Variable | Description | Default Value | Required |
| :--- | :--- | :--- | :--- |
| `JIRA_USER_EMAIL` | Your Jira user email (used with API Token authentication). | None | **Yes** |
| `JIRA_API_TOKEN` | Your Jira API token. **Highly Recommended** to use a dedicated token. | None | **Yes** |
| `GITLAB_API_TOKEN` | A GitLab Private Token with `api` scope, required to fetch job logs. | None | **Yes (for full functionality)** |
| `JIRA_BASE_URL` | The base URL for your Jira instance (e.g., `https://mycompany.atlassian.net`). | `https://your-domain.atlassian.net` | Yes |
| `GITLAB_WEBHOOK_SECRET` | The secret token configured in your GitLab webhook settings. | None | No (But recommended for security) |
| `GITLAB_BASE_URL` | The base URL for your GitLab instance. | `https://gitlab.com` | Yes |
| `JIRA_PROJECT_KEY` | The Jira project key where tickets will be created (e.g., `DEVOPSTASKS`). | `DEVOPSTASKS` | Yes |
| `JIRA_ISSUE_TYPE_ID` | The ID of the Jira Issue Type to create (e.g., Task, Bug). | `10001` | Yes |
| `JIRA_CLOSE_TRANSITION_ID`| The ID of the transition to move the ticket to a "Done" or "Closed" state. | `31` | Yes |

### Important Notes on Watchers

The automatic watcher feature relies on two critical conditions:

1.  The **commit author's email** must be present in the GitLab webhook payload.
2.  The commit author's email must match an **active user's email in your Jira instance** so the bot can look up their Jira Account ID.

## 🚀 Deployment

The bot is built using **FastAPI** and **uvicorn**. It is ideal for deployment as a containerized service (e.g., Docker, Google Cloud Run, AWS ECS).

### 1. Installation

```
# Clone the repository
git clone https://github.com/lydacious/GitLab-Jira-Webhook-Bot
cd gitlab-jira-webhook-bot

# Install dependencies (requests, fastapi, uvicorn, pydantic)
pip install -r requirements.txt
```
### 2. Running Locally

You can run the bot locally for testing:
```
# Set environment variables (replace with your actual values)
export JIRA_USER_EMAIL="your-email@example.com"
export JIRA_API_TOKEN="your-jira-api-token"
export GITLAB_API_TOKEN="your-gitlab-private-token"
export JIRA_PROJECT_KEY="DEVOPSTASKS"
export GITLAB_WEBHOOK_SECRET="your-gitlab-secret"

# Start the application
python gitlab_jira_webhook_bot.py
```
The bot will be running on `http://0.0.0.0:8080`.

### 3. Configuring the GitLab Webhook

In your GitLab project settings:

1.  Go to **Settings** -> **Webhooks**.
2.  Set the **URL** to your bot's endpoint: `http://<your-bot-host>:8080/gitlab-pipeline`
3.  Check the **Pipeline events** trigger.
4.  If configured, enter the value for `GITLAB_WEBHOOK_SECRET` into the **Secret token** field.
5.  Click **Add webhook**.
