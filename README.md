
```
mysql

create database wordpress;
alter user root@localhost identified with mysql_native_password by 'root';

Edit /app/wp-config.php
- define('FS_METHOD', 'direct');

chmod -R 777 /appwp-content/

```

