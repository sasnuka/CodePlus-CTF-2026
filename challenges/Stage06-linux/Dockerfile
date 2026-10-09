FROM lscr.io/linuxserver/openssh-server:latest

RUN mkdir -p /challenge/backups && \
    echo "CodePlus Campus Backend Server" > /challenge/README.txt && \
    echo "Security Notice: Review the backup directory and file permissions." >> /challenge/README.txt && \
    echo "CODEPLUS{campus_breach_resolved}" > /challenge/backups/final_backup.txt && \
    chmod 755 /challenge && \
    chmod 755 /challenge/backups && \
    chmod 644 /challenge/README.txt && \
    chmod 644 /challenge/backups/final_backup.txt

EXPOSE 2222