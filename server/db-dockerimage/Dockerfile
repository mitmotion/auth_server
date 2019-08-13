FROM postgres:11.5
RUN echo "host all  all    0.0.0.0/0  md5" >> /etc/postgresql/11.5/main/pg_hba.conf
RUN echo "listen_addresses='*'" >> /etc/postgresql/11.5/main/postgresql.conf
CMD ["postgres"]
