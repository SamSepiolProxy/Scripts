param(
    [string]$Token
)

# Set the Graph API endpoints
$ListMessagesUrl = "https://graph.microsoft.com/v1.0/me/messages"

# Define headers for authentication
$Headers = @{
    'Authorization' = "Bearer $Token"
    'Content-Type'  = 'application/json'
}

# Fetch list of messages
$MessagesResponse = Invoke-RestMethod -Uri $ListMessagesUrl -Headers $Headers -Method Get

# Check if we received messages
if ($MessagesResponse.value) {
    foreach ($Message in $MessagesResponse.value) {
        $MessageId = $Message.id
        $GetMessageUrl = "https://graph.microsoft.com/v1.0/me/messages/$MessageId"
        
        # Fetch individual message details
        $MessageDetail = Invoke-RestMethod -Uri $GetMessageUrl -Headers $Headers -Method Get
        
        # Extract email body content
        $EmailBody = $MessageDetail.body.content
        
        # Define file name using message ID
        $FileName = "$MessageId.html"
        
        # Save email body to a text file
        $EmailBody | Out-File -FilePath $FileName -Encoding UTF8
        
        Write-Output "Saved email to $FileName"
        
        # Fetch attachments
        $GetAttachmentsUrl = "https://graph.microsoft.com/v1.0/me/messages/$MessageId/attachments"
        $AttachmentsResponse = Invoke-RestMethod -Uri $GetAttachmentsUrl -Headers $Headers -Method Get
        
        if ($AttachmentsResponse.value) {
            foreach ($Attachment in $AttachmentsResponse.value) {
                $AttachmentId = $Attachment.id
                $GetAttachmentUrl = "https://graph.microsoft.com/v1.0/me/messages/$MessageId/attachments/$AttachmentId"
                
                # Fetch individual attachment details
                $AttachmentDetail = Invoke-RestMethod -Uri $GetAttachmentUrl -Headers $Headers -Method Get
                
                # Save attachment content if it's a file
                if ($AttachmentDetail."@odata.type" -eq "#microsoft.graph.fileAttachment") {
                    $AttachmentFileName = $AttachmentDetail.name
                    $AttachmentContentBytes = [System.Convert]::FromBase64String($AttachmentDetail.contentBytes)
                    [System.IO.File]::WriteAllBytes($AttachmentFileName, $AttachmentContentBytes)
                    
                    Write-Output "Saved attachment: $AttachmentFileName"
                }
            }
        }
    }
} else {
    Write-Output "No messages found."
}