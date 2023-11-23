FROM ubuntu:20.04

RUN sed -i 's@archive.ubuntu.com@mirror.kakao.com@g' /etc/apt/sources.list

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update --fix-missing && apt-get install -y  nodejs npm aria2 curl wget virtualenvwrapper git && \
    /bin/bash -c "$(curl -sL https://git.io/vokNn) " && \
    apt-fast update && apt-fast -y upgrade && apt-fast update --fix-missing

###### Download Chromium ######
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - 
RUN sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list'
RUN apt update -y
RUN apt-get install google-chrome-stable -y

RUN apt-fast install -y git build-essential  \
                        libxml2-dev libxslt1-dev libffi-dev cmake libreadline-dev \
                        libtool debootstrap debian-archive-keyring libglib2.0-dev libpixman-1-dev \
                        libssl-dev qtdeclarative5-dev libcapnp-dev libtool-bin \
                        libsqlite3-dev autoconf re2c  libonig-dev libcurl4-openssl-dev \
                        libcurl4-openssl-dev libpng-dev libgmp-dev libzip-dev libjpeg-dev \
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

##################### APACHE INSTALL ##########################

RUN wget https://dlcdn.apache.org/httpd/httpd-2.4.58.tar.gz
RUN tar zxvf httpd-2.4.58.tar.gz

RUN wget https://dlcdn.apache.org//apr/apr-1.7.4.tar.gz
RUN tar zxvf apr-1.7.4.tar.gz
RUN mv apr-1.7.4 httpd-2.4.58/srclib/apr

RUN wget https://dlcdn.apache.org//apr/apr-util-1.6.3.tar.gz
RUN tar zxvf apr-util-1.6.3.tar.gz
RUN mv apr-util-1.6.3 httpd-2.4.58/srclib/apr-util

ENV  CFLAGS="-DBIG_SECURITY_HOLE"
RUN  cd httpd-2.4.58 && export CFLAGS && ./configure --prefix=/usr/local/apache \
    --enable-rewrite=shared \
    --enable-speling=shared \
    --with-included-apr && make && make install

COPY httpd.conf /usr/local/apache/conf/httpd.conf

RUN mkdir /var/run/apache2 && chmod 777 -R /var/run/apache2

####################### LD_PRELOAD ######################
COPY /wclibs/lib_db_fault_escalator.so /lib/lib_db_fault_escalator.so

RUN rm -f /wclibs/lib_db_fault_escalator.so && \
    ln -s /lib/lib_db_fault_escalator.so /lib/libcgiwrapper.so && \
    ln -s /lib/lib_db_fault_escalator.so /wclibs/lib_db_fault_escalator.so

COPY php7 /phpsrc 

RUN cd /phpsrc && ./buildconf --force

RUN cd /phpsrc &&         \
        ./configure       \
        --with-apxs2=/usr/local/apache/bin/apxs \
		--enable-cgi      \
		--enable-ftp      \
		--enable-mbstring \
        --enable-exif \
        --enable-intl \
		--enable-gd         \
        --with-jpeg \
		--with-gettext \
		--with-openssl \
		--with-curl \
		--with-mysql      \
		--with-ssl      \
		--with-mysqli      \
		--with-pdo-mysql  \
		--with-zlib \
        --with-zip

RUN cd /phpsrc \
	&& make clean &&  EXTRA_CFLAGS="-DWITCHER_DEBUG=1" make -j $(nproc)

RUN cd /phpsrc && make install

RUN sed -i "s/.*bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/my.cnf && \
  sed -i "s/.*bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/mysql.conf.d/mysqld.cnf

COPY config/supervisord.conf /etc/supervisord.conf
COPY config/php.ini /usr/local/lib/php.ini

RUN rm -fr /var/www/html && ln -s /app /var/www/html

### Composer install

RUN curl -sS https://getcomposer.org/installer | sudo php -- --install-dir=/usr/local/bin/
RUN sudo ln -s /usr/local/bin/composer.phar /usr/local/bin/composer

#### XDEBUG

COPY xdebug /xdebug

RUN cd /xdebug && phpize && ./configure --enable-xdebug && make -j $(nproc) && make install

RUN git clone https://github.com/krakjoe/uopz.git

RUN cd /uopz && phpize && ./configure --enable-uopz && make -j $(nproc) && make install

RUN mkdir /home/tmp
RUN chmod 777 -R /home/tmp

COPY hook.php /lib/hook.php

RUN printf '\nauto_prepend_file=/lib/hook.php\nextension=uopz\nuopz.exit=1\n\n' >> $(php -i |egrep "Loaded Configuration File.*php.ini"|cut -d ">" -f2|cut -d " " -f2)

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
ENV PATH=$PATH:/usr/local/go/bin

RUN git clone https://github.com/BoB-WebFuzzing/fuzzer.git && cd /fuzzer && make
RUN git clone https://github.com/BoB-WebFuzzing/WTF-crawlergo.git && cd /WTF-crawlergo && make build

######## DASH ######

COPY dash /dash
RUN chmod 777 /dash && cp -rf /dash /bin/dash

####### FUZZER TEST #######

COPY client_test /

CMD /netconf.sh && /usr/bin/supervisord
