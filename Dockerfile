FROM ubuntu:20.04

RUN sed -i 's@archive.ubuntu.com@mirror.kakao.com@g' /etc/apt/sources.list

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update --fix-missing && apt-get install -y  nodejs npm aria2 curl wget virtualenvwrapper git && \
    /bin/bash -c "$(curl -sL https://git.io/vokNn) " && \
    apt-fast update && apt-fast -y upgrade && apt-fast update --fix-missing

RUN apt-fast install -y git build-essential  \
                        libxml2-dev libxslt1-dev libffi-dev cmake libreadline-dev \
                        libtool debootstrap debian-archive-keyring libglib2.0-dev libpixman-1-dev \
                        libssl-dev qtdeclarative5-dev libcapnp-dev libtool-bin \
                        libsqlite3-dev autoconf re2c  libonig-dev libcurl4-openssl-dev \
                        libcurl4-openssl-dev libpng-dev libgmp-dev \
                        python3-pip python3-pexpect ipython3 \
                        sudo openssh-server automake rsync net-tools netcat  \
                        ccache make g++-multilib pkg-config coreutils rsyslog \
                        manpages-dev ninja-build capnproto  software-properties-common zip unzip pwgen \
                        openssh-server mysql-server \
                        vim qemu gdb patchelf apache2 apache2-dev supervisor \
                        autoconf bison

RUN rm -rf /var/lib/mysql
RUN  /usr/sbin/mysqld --initialize-insecure

RUN mkdir /app

COPY config/supervisord.conf /etc/supervisord.conf
RUN if [ ! -d /run/sshd ]; then mkdir /run/sshd; chmod 0755 /run/sshd; fi
RUN mkdir /var/run/mysqld ; chown mysql:mysql /var/run/mysqld

COPY config/network_config.sh /netconf.sh
RUN chmod +x /netconf.sh

COPY afl /afl
RUN cd /afl && make
ENV AFL_PATH=/afl

COPY wclibs /wclibs

####################### LD_PRELOAD ######################
COPY /wclibs/lib_db_fault_escalator.so /lib/lib_db_fault_escalator.so

RUN rm -f /wclibs/lib_db_fault_escalator.so && \
    ln -s /lib/lib_db_fault_escalator.so /lib/libcgiwrapper.so && \
    ln -s /lib/lib_db_fault_escalator.so /wclibs/lib_db_fault_escalator.so

COPY php8 /phpsrc 

RUN cd /phpsrc && ./buildconf --force

RUN cd /phpsrc &&         \
        ./configure       \
        --with-apxs2=/usr/bin/apxs \
		--enable-cgi      \
		--enable-ftp      \
		--enable-mbstring \
        --enable-exif \
        --enable-intl \
		--enable-gd         \
		--with-gettext \
		--with-openssl \
		--with-curl \
		--with-mysql      \
		--with-ssl      \
		--with-mysqli      \
		--with-pdo-mysql  \
		--with-zlib

RUN cd /phpsrc \
	&& make clean &&  EXTRA_CFLAGS="-DWITCHER_DEBUG=1" make -j $(nproc)

RUN cd /phpsrc && make install


ENV APACHE_RUN_DIR=/etc/apache2/
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf


RUN sed -i "s/.*bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/my.cnf && \
  sed -i "s/.*bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/mysql.conf.d/mysqld.cnf

RUN rm -f /etc/apache2/mods-enabled/mpm_event.* \
    && rm -f /etc/apache2/mods-enabled/mpm_prefork.* \
    && ln -s /etc/apache2/mods-available/mpm_prefork.load /etc/apache2/mods-enabled/mpm_prefork.load \
    && ln -s /etc/apache2/mods-available/mpm_prefork.conf /etc/apache2/mods-enabled/mpm_prefork.conf

COPY config/supervisord.conf /etc/supervisord.conf
COPY config/php.ini /usr/local/lib/php.ini
COPY config/php.ini /etc/php/8.3/apache2/php.ini
COPY config/php8.conf config/php8.load /etc/apache2/mods-available/

RUN ln -f -s /etc/apache2/mods-available/php8.load /etc/apache2/mods-enabled/ && ln -f -s /etc/apache2/mods-available/php8.conf /etc/apache2/mods-enabled/

RUN a2enmod rewrite
RUN rm -fr /var/www/html && ln -s /app /var/www/html

### Composer install

RUN curl -sS https://getcomposer.org/installer | sudo php -- --install-dir=/usr/local/bin/
RUN sudo ln -s /usr/local/bin/composer.phar /usr/local/bin/composer

#### XDEBUG

COPY xdebug /xdebug

RUN cd /xdebug && phpize && ./configure --enable-xdebug && make -j $(nproc) && make install

# disable directory browsing in apache2
RUN sed -i 's/Indexes//g' /etc/apache2/apache2.conf && \
    echo "DirectoryIndex index.php index.phtml index.html index.htm" >> /etc/apache2/apache2.conf

# add index
COPY config/000-default.conf /etc/apache2/sites-available/

RUN printf '\nzend_extension=/usr/local/lib/php/extensions/no-debug-non-zts-20230901/xdebug.so\nxdebug.mode=coverage\nauto_prepend_file=/enable_cc.php\n\n' >> $(php -i |egrep "Loaded Configuration File.*php.ini"|cut -d ">" -f2|cut -d " " -f2)
RUN for fn in $(find /etc/php/ . -name 'php.ini'); do printf '\nzend_extension=/usr/local/lib/php/extensions/no-debug-non-zts-20230901/xdebug.so\nxdebug.mode=coverage\nauto_prepend_file=/enable_cc.php\n\n' >> $fn; done

COPY config/codecov_conversion.py config/enable_cc.php /

RUN mkdir /tmp/coverages

######## WORDPRESS INSTALL ######

WORKDIR /app/
RUN wget https://ko.wordpress.org/latest-ko_KR.zip && unzip latest-ko_KR.zip
RUN mv wordpress/* ./ && rmdir wordpress

######## Install NVM , Upgrade Node version #######
ENV NVM_DIR /root/.nvm 

RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.5/install.sh | bash

RUN . $NVM_DIR/nvm.sh && nvm install 20 && nvm use 20
######## Install Golang & GoFuzzer, CrawlerGo #######

WORKDIR /

RUN wget https://go.dev/dl/go1.21.3.linux-amd64.tar.gz
RUN rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.3.linux-amd64.tar.gz

RUN git clone https://github.com/shirohacker/fuzzer.git && cd /fuzzer
RUN git clone https://github.com/shirohacker/crawlergo.git && cd /crawlergo

######## DASH ######

COPY dash /dash
RUN chmod 777 /dash && cp -rf /dash /bin/dash

####### FUZZER TEST #######

COPY client_test /

CMD /netconf.sh && /usr/bin/supervisord
