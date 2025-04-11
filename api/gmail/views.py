from django.shortcuts import redirect
from django.http import JsonResponse, FileResponse, HttpResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import json
import base64
import logging
import mimetypes
import os
import imghdr
import redis
import hashlib
import time
import uuid
import datetime
from googleapiclient.http import MediaInMemoryUpload

# Initialize logger
logger = logging.getLogger(__name__)


class BaseGmailView(View):
    """Base class for Gmail views"""
    
    def dispatch(self, request, *args, **kwargs):
        self.credentials = self.get_credentials(request)
        if not self.credentials:
            return redirect('/gmail/auth/')
        
        try:
            service = build('oauth2', 'v2', credentials=self.credentials)
            user_info = service.userinfo().get().execute()
            self.user_email = user_info.get('email')
        except Exception as e:
            logger.error(f"Error getting user email: {str(e)}")
            self.user_email = None
            
        return super().dispatch(request, *args, **kwargs)
    
    def get_credentials(self, request):
        if 'credentials' not in request.session:
            return None
            
        try:
            creds_info = json.loads(request.session['credentials'])
            creds = Credentials.from_authorized_user_info(creds_info)
            
            if not creds.valid:
                if creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                    request.session['credentials'] = creds.to_json()
                else:
                    return None
                    
            return creds
        except Exception as e:
            logger.error(f"Error getting credentials: {str(e)}")
            return None

@method_decorator(csrf_exempt, name='dispatch')
class GmailListMessagesView(BaseGmailView):
    """Handle listing emails"""
    
    def get(self, request):
        try:
            service = build('gmail', 'v1', credentials=self.credentials)
            
            results = service.users().messages().list(
                userId='me',
                maxResults=10,
                labelIds=['INBOX']
            ).execute()
            
            messages = []
            for msg in results.get('messages', []):
                message = service.users().messages().get(
                    userId='me',
                    id=msg['id'],
                    format='metadata',
                    metadataHeaders=['From', 'Subject', 'Date']
                ).execute()
                
                headers = message['payload']['headers']
                email_data = {
                    'id': message['id'],
                    'from': next(
                        (header['value'] for header in headers if header['name'] == 'From'),
                        'Unknown'
                    ),
                    'subject': next(
                        (header['value'] for header in headers if header['name'] == 'Subject'),
                        'No Subject'
                    ),
                    'date': next(
                        (header['value'] for header in headers if header['name'] == 'Date'),
                        'No Date'
                    ),
                    'snippet': message.get('snippet', ''),
                }
                messages.append(email_data)
            
            return JsonResponse({
                'messages': messages,
                'user_email': self.user_email
            })
            
        except Exception as e:
            logger.error(f"Email listing error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class GmailMessageDetailView(BaseGmailView):
    """Handle getting email details"""
    
    def get(self, request, message_id):
        try:
            service = build('gmail', 'v1', credentials=self.credentials)
            
            message = service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()
            
            headers = message['payload']['headers']
            email_data = {
                'id': message['id'],
                'from': next(
                    (header['value'] for header in headers if header['name'] == 'From'),
                    'Unknown'
                ),
                'to': next(
                    (header['value'] for header in headers if header['name'] == 'To'),
                    'Unknown'
                ),
                'subject': next(
                    (header['value'] for header in headers if header['name'] == 'Subject'),
                    'No Subject'
                ),
                'date': next(
                    (header['value'] for header in headers if header['name'] == 'Date'),
                    'No Date'
                ),
            }
            
            if 'parts' in message['payload']:
                parts = message['payload']['parts']
                body = ''
                attachments = []
                
                for part in parts:
                    if part['mimeType'] == 'text/plain':
                        if 'data' in part['body']:
                            body += base64.urlsafe_b64decode(
                                part['body']['data']
                            ).decode('utf-8')
                    elif 'filename' in part and part['filename']:
                        attachments.append({
                            'id': part['body'].get('attachmentId'),
                            'filename': part['filename'],
                            'mimeType': part['mimeType']
                        })
                
                email_data['body'] = body
                email_data['attachments'] = attachments
            else:
                if 'data' in message['payload']['body']:
                    email_data['body'] = base64.urlsafe_b64decode(
                        message['payload']['body']['data']
                    ).decode('utf-8')
                else:
                    email_data['body'] = ''
                email_data['attachments'] = []
            
            return JsonResponse(email_data)
            
        except Exception as e:
            logger.error(f"Email detail error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
@method_decorator(csrf_exempt, name='dispatch')
class GmailAttachmentView(BaseGmailView):
    def get(self, request, message_id, attachment_id):
        try:
            service = build('gmail', 'v1', credentials=self.credentials)
            
            # First get the message to find attachment details
            message = service.users().messages().get(
                userId='me',
                id=message_id
            ).execute()

            # Find the attachment part
            attachment_part = None
            for part in message['payload'].get('parts', []):
                if part.get('body', {}).get('attachmentId') == attachment_id:
                    attachment_part = part
                    break

            if not attachment_part:
                logger.error(f"Attachment {attachment_id} not found in message {message_id}")
                return JsonResponse({"error": "Attachment not found"}, status=404)

            # Get the attachment data
            attachment = service.users().messages().attachments().get(
                userId='me',
                messageId=message_id,
                id=attachment_id
            ).execute()

            if not attachment.get('data'):
                logger.error(f"No data found for attachment {attachment_id}")
                return JsonResponse({"error": "Attachment data not found"}, status=404)

            # Decode the attachment data
            file_data = base64.urlsafe_b64decode(attachment['data'])
            
            content_type = attachment_part.get('mimeType', 'application/octet-stream')
            filename = attachment_part.get('filename', 'attachment')
            
            response = HttpResponse(file_data, content_type=content_type)
            response['Content-Disposition'] = f'inline; filename="{filename}"'
            return response

        except Exception as e:
            logger.error(f"Attachment view error: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)
import imghdr
        
@method_decorator(csrf_exempt, name='dispatch')
class GmailAttachmentDownloadView(BaseGmailView):
    """Handle downloading email attachments"""
    
    def detect_file_type(self, base64_data):
        file_data = base64.urlsafe_b64decode(base64_data)

        signatures = [
            (b'%PDF', 'PDF', 'application/pdf', '.pdf'),
            (b'\x89PNG\r\n\x1a\n', 'PNG', 'image/png', '.png'),
            (b'\xff\xd8\xff', 'JPEG', 'image/jpeg', '.jpg'),
            (b'GIF8', 'GIF', 'image/gif', '.gif'),
            (b'PK\x03\x04', 'ZIP/DOCX/XLSX/PPTX', 'application/zip', '.zip'),
            (b'ID3', 'MP3', 'audio/mpeg', '.mp3'),
            (b'\xff\xfb', 'MP3', 'audio/mpeg', '.mp3'),
            (b'\x00\x00\x00\x18ftyp', 'MP4', 'video/mp4', '.mp4'),
            (b'Rar!\x1a\x07\x00', 'RAR', 'application/x-rar-compressed', '.rar'),
            (b'MZ', 'EXE', 'application/vnd.microsoft.portable-executable', '.exe'),
            (b'{\\rtf1', 'RTF', 'application/rtf', '.rtf'),
            (b'<!DOC', 'HTML', 'text/html', '.html'),
            (b'<html', 'HTML', 'text/html', '.html'),
            (b'{', 'JSON', 'application/json', '.json'),
            (b'[', 'JSON', 'application/json', '.json'),
        ]

        for sig, name, mime, ext in signatures:
            if file_data.startswith(sig):
                return {
                    'type': name,
                    'mime': mime,
                    'extension': ext
                }

        # Default fallback
        return {
            'type': 'Unknown',
            'mime': 'application/octet-stream',
            'extension': ''
        }
   
    def get(self, request, message_id, attachment_id):
            try:
                try:
                    redis_client = redis.Redis(
                        host='localhost',
                        port=6379,
                        db=0,
                        password=None,
                        decode_responses=False 
                    )
                    logger.info("Redis connection initialized for attachment storage")
                except Exception as e:
                    logger.error(f"Failed to connect to Redis: {str(e)}")
                    return JsonResponse({"error": f"Redis connection failed: {str(e)}"}, status=500)
                
                service = build('gmail', 'v1', credentials=self.credentials)
                attachment = service.users().messages().attachments().get(
                    userId='me',
                    messageId=message_id,
                    id=attachment_id
                ).execute()
                
                if not attachment.get('data'):
                    return JsonResponse({"error": "Attachment data not found"}, status=404)
                
                file_type_info = self.detect_file_type(attachment['data'])
                logger.info(f"Detected file type: {file_type_info['type']}, MIME: {file_type_info['mime']}")
                    
                message = service.users().messages().get(
                    userId='me',
                    id=message_id,
                    format='full'
                ).execute()
                filename = None
                mime_type = None

                if 'payload' in message and 'parts' in message['payload']:
                    for part in message['payload']['parts']:
                        if part.get('filename') and part.get('body', {}).get('attachmentId'):
                            filename = part.get('filename')
                            mime_type = part.get('mimeType')
                            break            
                
                if not filename:
                    filename = f"attachment_{attachment_id}"
                
                if file_type_info['extension']:
                    if '.' in filename:
                        base_name = filename.rsplit('.', 1)[0]
                        filename = f"{base_name}{file_type_info['extension']}"
                    else:
                        filename = f"{filename}{file_type_info['extension']}"
                
                file_data = base64.urlsafe_b64decode(attachment['data'])
                
                # Generate a unique ID for the file
                file_id = str(uuid.uuid4())
                
                # Create file metadata
                file_metadata = {
                    'id': file_id,
                    'name': filename,
                    'size': len(file_data),
                    'content_type': mime_type or file_type_info['mime'],
                    'file_type': file_type_info['type'],
                    'message_id': message_id,
                    'attachment_id': attachment_id,
                    'user_email': self.user_email,
                    'upload_date': datetime.datetime.now().isoformat()
                }
                
                # Store in Redis
                pipeline = redis_client.pipeline()
                file_key = f"gmail:file:{self.user_email}:{file_id}"
                pipeline.set(file_key, file_data)
                pipeline.expire(file_key, 86400) 
                meta_key = f"gmail:file:{self.user_email}:{file_id}:meta"
                pipeline.set(meta_key, json.dumps(file_metadata))
                pipeline.expire(meta_key, 86400)
                pipeline.execute()
                logger.info(f"Stored file in Redis: {file_id}, {filename}, {len(file_data)} bytes")
                
                # Upload to Google Drive
                drive_service = build('drive', 'v3', credentials=self.credentials)
                
                # Prepare the media upload object
                media = MediaInMemoryUpload(file_data, 
                                           mimetype=mime_type or file_type_info['mime'],
                                           resumable=True)
                
                # Prepare the file metadata for Drive
                drive_file_metadata = {
                    'name': filename,
                    'description': f'Email attachment from message {message_id}',
                    'mimeType': mime_type or file_type_info['mime']
                }
                
                # Execute the upload
                drive_file = drive_service.files().create(
                    body=drive_file_metadata,
                    media_body=media,
                    fields='id, name, webViewLink, webContentLink'
                ).execute()
                
                logger.info(f"Uploaded file to Google Drive: {drive_file.get('id')}, {filename}")
                
                # Update Redis metadata with Drive info
                file_metadata['drive_file_id'] = drive_file.get('id')
                file_metadata['drive_web_link'] = drive_file.get('webViewLink')
                file_metadata['drive_download_link'] = drive_file.get('webContentLink')
                
                # Update the metadata in Redis
                redis_client.set(meta_key, json.dumps(file_metadata))
                
                return JsonResponse({
                    "status": "success",
                    "message": f"File '{filename}' stored in Redis and uploaded to Drive successfully",
                    "file_id": file_id,
                    "filename": filename,
                    "content_type": mime_type or file_type_info['mime'],
                    "size": len(file_data),
                    "file_type": file_type_info['type'],
                    "expiry": "24 hours",
                    "drive": {
                        "file_id": drive_file.get('id'),
                        "web_link": drive_file.get('webViewLink'),
                        "download_link": drive_file.get('webContentLink')
                    }
                })
                
            except Exception as e:
                logger.error(f"Attachment storage/upload error: {str(e)}")
                return JsonResponse({"error": str(e)}, status=500)
    
@method_decorator(csrf_exempt, name='dispatch')
class GmailAttachmentRedisListView(BaseGmailView):
    """Handle listing email attachments stored in Redis"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Redis configuration directly in the class
        self.redis_config = {
            'host': 'localhost',
            'port': 6379,
            'db': 0,
            'password': None,
            'decode_responses': True  # For metadata we want decoded responses
        }
        
        # Initialize Redis connection
        try:
            self.redis_client = redis.Redis(**self.redis_config)
            logger.info("Redis connection initialized for attachment listing")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {str(e)}")
            self.redis_client = None
    
    def get(self, request):
        """List all attachments stored in Redis for the current user"""
        if not self.redis_client:
            return JsonResponse({"error": "Redis connection not available"}, status=500)
            
        try:
            # Pattern to search for user's attachments metadata
            pattern = f"gmail:attachment:{self.user_email}:*:meta"
            # OR pattern for file storage scheme
            file_pattern = f"gmail:file:{self.user_email}:*:meta"
            
            # Get all keys matching the pattern
            attachment_keys = self.redis_client.keys(pattern)
            file_keys = self.redis_client.keys(file_pattern)
            
            all_keys = attachment_keys + file_keys
            
            attachments = []
            
            for key in all_keys:
                try:
                    metadata_json = self.redis_client.get(key)
                    if metadata_json:
                        metadata = json.loads(metadata_json)
                        
                        # Extract file hash from key
                        # Key format is either gmail:attachment:email:hash:meta or gmail:file:email:hash:meta
                        key_parts = key.split(':')
                        if len(key_parts) >= 4:
                            file_hash = key_parts[3]
                            
                            storage_type = key_parts[1]  # "attachment" or "file"
                            metadata['retrieval_url'] = f"/gmail/{storage_type}/retrieve/{file_hash}/"
                            
                            ttl = self.redis_client.ttl(key)
                            if ttl > 0:
                                metadata['expires_in_seconds'] = ttl
                                expiry_time = datetime.datetime.now() + datetime.timedelta(seconds=ttl)
                                metadata['expires_at'] = expiry_time.isoformat()
                            else:
                                metadata['expires_in_seconds'] = 'unknown'
                                metadata['expires_at'] = 'unknown'
                                
                            metadata['file_hash'] = file_hash
                            attachments.append(metadata)
                except Exception as e:
                    logger.error(f"Error processing Redis key {key}: {str(e)}")
                    continue
            
            attachments.sort(
                key=lambda x: x.get('timestamp', x.get('upload_date', '0')),
                reverse=True
            )
            
            return JsonResponse({
                "status": "success",
                "count": len(attachments),
                "user_email": self.user_email,
                "attachments": attachments
            })
            
        except Exception as e:
            logger.error(f"Error listing Redis attachments: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)
    def _find_parts_recursively(self, payload):
        """Helper method to find all parts in a message payload"""
        if not payload:
            return []
            
        parts = []
        # Add current part if it has a body
        if 'body' in payload:
            parts.append(payload)
            
        # Search in child parts
        if 'parts' in payload:
            for part in payload['parts']:
                parts.extend(self._find_parts_recursively(part))
                
        return parts
    
    #####################
