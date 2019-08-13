FROM postgres:11.5
RUN echo "max_connections = 512" >> /etc/postgresql.conf
RUN echo "shared_buffers = 128MB" >> /etc/postgresql.conf
CMD ["postgres"]
