FROM postgres:11.5
RUN echo "max_connections = 512" >> /var/lib/pgsql/data/postgresql.conf
RUN echo "shared_buffers = 128MB" >> /var/lib/pgsql/data/postgresql.conf
CMD ["postgres"]
