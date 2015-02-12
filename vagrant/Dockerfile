FROM phusion/baseimage

RUN rm -f /etc/service/sshd/down

#CMD ["/sbin/my_init","--enable-insecure-key"]
CMD ["/sbin/my_init"]

RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
