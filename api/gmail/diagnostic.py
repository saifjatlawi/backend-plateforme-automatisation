import os
import json
import base64
import logging
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("gmail_attachment_debug.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_credentials(session_file):
    """Load credentials from a session file"""
    try:
        with open(session_file, 'r') as f:
            creds_info = json.load(f)
        
        creds = Credentials.from_authorized_user_info(creds_info)
        
        if not creds.valid:
            if creds.expired and creds.refresh_token:
                creds.refresh(Request())
                # Save the refreshed credentials
                with open(session_file, 'w') as f:
                    f.write(creds.to_json())
            else:
                logger.error("Credentials are invalid and cannot be refreshed")
                return None
                
        return creds
    except Exception as e:
        logger.error(f"Error loading credentials: {str(e)}")
        return None

def get_message_structure(service, message_id):
    """Get detailed message structure"""
    try:
        message = service.users().messages().get(
            userId='me',
            id=message_id,
            format='full'
        ).execute()
        
        logger.info(f"Successfully retrieved message: {message_id}")
        return message
    except Exception as e:
        logger.error(f"Error getting message: {str(e)}")
        return None

def find_all_attachments(payload, path="root"):
    """Find all attachments in the message recursively"""
    attachments = []
    
    if not payload:
        return attachments
    
    mime_type = payload.get('mimeType', '')
    logger.info(f"Examining part at path {path} with mimeType: {mime_type}")
    
    # Check if this part has an attachment ID
    if 'body' in payload and 'attachmentId' in payload.get('body', {}):
        attachment_info = {
            'id': payload['body']['attachmentId'],
            'filename': payload.get('filename', 'unnamed'),
            'mimeType': mime_type,
            'size': payload.get('body', {}).get('size', 0),
            'path': path
        }
        logger.info(f"Found attachment: {attachment_info}")
        attachments.append(attachment_info)
    
    # Check all child parts recursively
    if 'parts' in payload:
        for i, part in enumerate(payload['parts']):
            child_path = f"{path}.parts[{i}]"
            attachments.extend(find_all_attachments(part, child_path))
    
    return attachments

def test_attachment_download(service, message_id, attachment_id):
    """Test downloading an attachment directly"""
    try:
        logger.info(f"Testing direct download of attachment: {attachment_id}")
        attachment = service.users().messages().attachments().get(
            userId='me',
            messageId=message_id,
            id=attachment_id
        ).execute()
        
        if attachment.get('data'):
            file_data = base64.urlsafe_b64decode(attachment['data'])
            logger.info(f"Successfully downloaded attachment: {len(file_data)} bytes")
            return True
        else:
            logger.warning("Attachment data is empty")
            return False
    except Exception as e:
        logger.error(f"Error downloading attachment: {str(e)}")
        return False

def main():
    # Config - update these values
    session_file = "c:\\Users\\lenovo\\Desktop\\Rapport-PFE-Code\\APIAutome\\session_credentials.json"
    message_id = "1960fae32d763f01"  # Update with the problematic message ID
    
    # Create logs directory if it doesn't exist
    logs_dir = "c:\\Users\\lenovo\\Desktop\\Rapport-PFE-Code\\APIAutome\\logs"
    os.makedirs(logs_dir, exist_ok=True)
    
    # Load credentials
    creds = load_credentials(session_file)
    if not creds:
        logger.error("Failed to load credentials")
        return
    
    # Build the Gmail service
    service = build('gmail', 'v1', credentials=creds)
    
    # Get message structure
    message = get_message_structure(service, message_id)
    if not message:
        return
    
    # Find all attachments
    attachments = find_all_attachments(message.get('payload', {}))
    
    # Log the results
    logger.info(f"Found {len(attachments)} attachments in message {message_id}")
    for att in attachments:
        logger.info(f"Attachment: {att['filename']} (ID: {att['id']})")
        
        # Test downloading each attachment
        success = test_attachment_download(service, message_id, att['id'])
        logger.info(f"Download test {'succeeded' if success else 'failed'} for {att['id']}")
    
    # Write detailed message structure to file
    with open(os.path.join(logs_dir, f"message_{message_id}_full.json"), "w") as f:
        json.dump(message, f, indent=2)
    
    logger.info(f"Detailed message structure written to logs/message_{message_id}_full.json")

if __name__ == "__main__":
    main()