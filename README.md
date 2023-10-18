
```
mysql

create database wordpress;
alter user root@localhost identified with mysql_native_password by 'root';

Edit /app/wp-config.php
- define('FS_METHOD', 'direct');

Edit /usr/local/lib/php.ini
- upload_max_filesize=200M;

chmod -R 777 /app/wp-content/

```

