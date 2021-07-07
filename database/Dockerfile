FROM mysql

# Add a database
ENV MYSQL_DATABASE prueba
# Add the content of the sql-scripts/ directory to your image
# All scripts in docker-entrypoint-initdb.d/ are automatically
# executed during container startup
COPY ./db.sql /docker-entrypoint-initdb.d/