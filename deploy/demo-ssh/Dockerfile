# KeepPAM demo SSH target (operator never sees this password in the portal).
FROM alpine:3.21
RUN apk add --no-cache openssh-server \
    && mkdir -p /var/run/sshd \
    && adduser -D -s /bin/sh demo \
    && echo 'demo:DemoPass!1' | chpasswd \
    && ssh-keygen -A \
    && printf '\nPasswordAuthentication yes\nPermitRootLogin no\nAllowUsers demo\n' >> /etc/ssh/sshd_config
COPY README.txt /home/demo/KEEP-PAM-README.txt
RUN chown demo:demo /home/demo/KEEP-PAM-README.txt
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
