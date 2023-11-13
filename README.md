

# mysql
```
create database wordpress;
alter user root@localhost identified by 'root';
```

# Wordpress settings
Edit /app/wp-config.php
- define('FS_METHOD', 'direct');

Edit /usr/local/lib/php.ini
- upload_max_filesize=200M;

Add permissions
```
chmod -R 777 /app/wp-content/
```

