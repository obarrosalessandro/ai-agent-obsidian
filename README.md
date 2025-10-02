# AI Agent for Obsidian

A powerful Obsidian plugin that connects with AI agents via webhooks for an intelligent chat experience within Obsidian.

## Features

- **AI-Powered Chat**: Seamlessly integrate with AI services through customizable webhooks
- **Note Integration**: Attach and process existing notes in your vault
- **Secure Communication**: Implements token-based authentication and URL validation
- **Data Encryption**: Sensitive information is stored with basic encryption
- **Note Export**: Save AI responses directly to your vault
- **Multiple File Processing**: Send all notes from a folder to n8n workflow

## Installation

1. Open Obsidian Settings
2. Go to "Community plugins"
3. Search for "AI Agent for Obsidian"
4. Install and enable the plugin

## Configuration

1. Open Settings → AI Agent for Obsidian
2. Enter your n8n webhook URL (HTTPS required)
3. Set your security token (optional but recommended)
4. Configure the default save path for notes

### Security Features

- **HTTPS Only**: Only HTTPS URLs are accepted to ensure secure communication
- **Private IP Blocking**: Prevents Server-Side Request Forgery (SSRF) by blocking private IP addresses
- **Token Authentication**: Optional token-based authentication for webhook requests
- **Data Encryption**: Webhook URLs and tokens are stored with basic encryption

## Usage

### Basic Chat

1. Open AI Agent for Obsidian from the sidebar
2. Type your message in the input area
3. Click send or press Enter (without Shift)

### Process Existing Notes

- Use the paperclip icon to attach the currently active note to your message
- Right-click on any note in the file explorer and select "Send all notes in this folder to n8n" to process multiple files at once

### Attach Active Note or Selected Text

- Click the paperclip icon to attach the currently active note or selected text
- Select "Attach active note" or "Attach selected text" from the menu
- The content will be pre-filled in the input area with instructions placeholder

### Attach Selected Text

- Select text in any note
- Right-click and choose "Send to AI Agent for Obsidian" from context menu

### Export Responses

- Right-click on any AI response in the AI Agent for Obsidian chat
- Select "Save selection as note" to save to your vault

### Process Multiple Files

- Right-click on any folder in the file explorer
- Select "Send all notes in this folder to n8n"

## Requirements

- Obsidian version 1.6.0 or higher
- Access to a webhook endpoint (commonly implemented with n8n, Zapier, or similar)

## Security

This plugin implements multiple security measures:
- Only HTTPS URLs are accepted
- Private IP addresses are blocked to prevent SSRF
- Sensitive data is encrypted at rest
- Optional token-based authentication for webhook requests

## Troubleshooting

- If webhook calls fail, check that your URL uses HTTPS
- Ensure your endpoint accepts POST requests with JSON payload
- Verify your security token matches between plugin and endpoint

## Support

For issues, questions, or feature requests, please open an issue in the repository.