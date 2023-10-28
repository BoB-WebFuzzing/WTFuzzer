## this base is used under the image name witcher, which is used by
FROM ubuntu:20.04
LABEL version="1.0"
RUN sed -i 's@archive.ubuntu.com@mirror.kakao.com@g' /etc/apt/sources.list

# Use the fastest APT repo
#COPY ./files/sources.list.with_mirrors /etc/apt/sources.list


ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update
# Install apt-fast to speed things up
RUN apt-get install -y aria2 curl wget virtualenvwrapper libsqlite3-dev autoconf re2c  libonig-dev


RUN apt-get install -y git

#APT-FAST installation
RUN /bin/bash -c "$(curl -sL https://git.io/vokNn) "

RUN apt-fast update && apt-fast -y upgrade && apt-fast update

# Install all APT packages

RUN apt-fast install -y git build-essential  \
                        #Libraries
                        libxml2-dev libxslt1-dev libffi-dev cmake libreadline-dev \
                        libtool debootstrap debian-archive-keyring libglib2.0-dev libpixman-1-dev \
                        libssl-dev qtdeclarative5-dev libcapnp-dev libtool-bin \
                        libcurl4-openssl-dev libpng-dev libgmp-dev \
                        # x86 Libraries
                        #libc6:i386 libgcc1:i386 libstdc++6:i386 libtinfo5:i386 zlib1g:i386 \
                        #python 3
                        python3-pip python3-pexpect ipython3 \
                        #Utils
                        sudo openssh-server automake rsync net-tools netcat  \
                        ccache make g++-multilib pkg-config coreutils rsyslog \
                        manpages-dev ninja-build capnproto  software-properties-common zip unzip pwgen \
                        # other stuff
                        openssh-server mysql-server \
                        # editors
                        vim emacs \
                        # analysis
                        afl++ qemu gdb patchelf \
                        # web
                        apache2 apache2-dev supervisor


RUN rm -rf /var/lib/mysql
RUN  /usr/sbin/mysqld --initialize-insecure

# PHP 7.3 installation
# RUN add-apt-repository -y ppa:ondrej/php && \
#    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4F4EA0AAE5267A6C
# RUN apt-fast update && apt-get update
# RUN apt-fast install -y php7.3-xdebug  libapache2-mod-php7.3 php7.3-mysql php7.3-apcu php7.1-mcrypt \
#                        php7.3-gd php7.3-xml php7.3-mbstring php7.3-gettext php7.3-zip php7.3-curl \
#                        php7.3-gmp php7.3-cli

# Create wc user
RUN useradd -s /bin/bash -m wc
# Add wc to sudo group
RUN usermod -aG sudo wc
RUN echo "wc ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

RUN su - wc -c "source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && mkvirtualenv -p `which python3` witcher"

######### Install phuzzer stuff
RUN apt-fast install -y libxss1 bison

RUN su - wc -c "source /home/wc/.virtualenvs/witcher/bin/activate && pip install protobuf termcolor "

RUN su - wc -c "source /home/wc/.virtualenvs/witcher/bin/activate && pip install git+https://github.com/etrickel/phuzzer"

######### last installs, b/c don't want to wait for phuzzer stuff again.
RUN apt-fast install -y jq
RUN wget https://github.com/sharkdp/bat/releases/download/v0.15.0/bat_0.15.0_amd64.deb -O /root/bat15.deb && sudo dpkg -i /root/bat15.deb


######### wc's environment setup
USER wc
WORKDIR /home/wc
RUN mkdir -p /home/wc/tmp/emacs-saves
RUN git clone -q https://github.com/etrickel/docker_env.git
RUN chown wc:wc -R . && cp -r /home/wc/docker_env/. .
COPY config/.bash_prompt /home/wc/.bash_prompt
RUN mkdir /home/wc/.ssh && cat pubkeys/* >> /home/wc/.ssh/authorized_keys && chmod 400 /home/wc/.ssh/* && rm -rf pubkeys

RUN echo 'source /usr/share/virtualenvwrapper/virtualenvwrapper.sh' >> /home/wc/.bashrc
RUN echo 'workon witcher' >> /home/wc/.bashrc

######### root's bash and emacs profile
RUN sudo cp -r /home/wc/docker_env/. /root/

######### NodeJS and NPM Setup
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash
RUN echo 'export NVM_DIR=$HOME/.nvm; . $NVM_DIR/nvm.sh; . $NVM_DIR/bash_completion' >> /home/wc/.bashrc
ENV NVM_DIR /home/wc/.nvm
RUN . $NVM_DIR/nvm.sh && nvm install 20
#RUN sudo mkdir /node_modules && sudo chown wc:wc /node_modules && sudo apt-get install -y npm
RUN sudo apt-get install -y npm
RUN . $NVM_DIR/nvm.sh && npm install npm@latest && npm install puppeteer cheerio

USER root
RUN mkdir /app && chown www-data:wc /app


COPY config/supervisord.conf /etc/supervisord.conf
RUN if [ ! -d /run/sshd ]; then mkdir /run/sshd; chmod 0755 /run/sshd; fi
RUN mkdir /var/run/mysqld ; chown mysql:mysql /var/run/mysqld
# mysql configuration for disk access, used when running 25+ containers on single system
# RUN printf "[mysqld]\ninnodb_use_native_aio = 0\n" >> /etc/mysql/my.cnf

RUN ln -s /p /projects

COPY config/network_config.sh /netconf.sh
RUN chmod +x /netconf.sh

ENV TZ=America/Phoenix
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN echo "export TZ=$TZ" >> /home/wc/.bashrc

RUN usermod -a -G www-data wc

#"Installing" the Witcher's Dash that abends on a parsing error when STRICT=1 is set.
#

#COPY --from=hacrs/build-httpreqr /Witcher/base/httpreqr/httpreqr /httpreqr
#COPY --chown=wc:wc /httpreqr/httpreqr.64 /httpreqr

COPY afl /afl
RUN cd /afl && make
ENV AFL_PATH=/afl

COPY --chown=wc:wc helpers/ /helpers/
COPY --chown=wc:wc phuzzer /helpers/phuzzer

RUN su - wc -c "source /home/wc/.virtualenvs/witcher/bin/activate &&  pip install archr ipdb "

RUN su - wc -c "source /home/wc/.virtualenvs/witcher/bin/activate &&  cd /helpers/phuzzer && pip install -e ."

COPY --chown=wc:wc witcher /witcher/
RUN su - wc -c "source /home/wc/.virtualenvs/witcher/bin/activate &&  cd /witcher && pip install -e ."

RUN su - wc -c "source /home/wc/.virtualenvs/witcher/bin/activate && pip install ipython "

COPY --chown=wc:wc wclibs /wclibs

####################### LD_PRELOAD ######################
# RUN rm -f /wclibs/libcgiwrapper.so && 
COPY /wclibs/lib_db_fault_escalator.so /lib/lib_db_fault_escalator.so

RUN rm -f /wclibs/lib_db_fault_escalator.so && \
    ln -s /lib/lib_db_fault_escalator.so /lib/libcgiwrapper.so && \
    ln -s /lib/lib_db_fault_escalator.so /wclibs/lib_db_fault_escalator.so

# RUN cd /wclibs && gcc -c -Wall -fpic db_fault_escalator.c && gcc -shared -o lib_db_fault_escalator.so db_fault_escalator.o -ldl

# RUN rm -f /wclibs/libcgiwrapper.so && ln -s /wclibs/lib_db_fault_escalator.so /wclibs/libcgiwrapper.so && ln -s /wclibs/lib_db_fault_escalator.so /lib/libcgiwrapper.so

########################################################## PHP BUILD ######################################

#COPY --chown=wc:wc bins /bins

ARG ARG_PHP_VER=8
ENV PHP_VER=${ARG_PHP_VER}
ENV PHP_INI_DIR="/etc/php/"
ENV LD_LIBRARY_PATH="/wclibs"
ENV PROF_FLAGS="-lcgiwrapper -I/wclibs"
ENV CPATH="/wclibs"

ENV CONTAINER_NAME="witcher"
ENV WC_TEST_VER="EXWICHR"
ENV WC_FIRST=""
ENV WC_CORES="10"
ENV WC_TIMEOUT="1200"
ENV WC_SET_AFFINITY="0"
# single script takes "--target scriptname"
ENV WC_SINGLE_SCRIPT=""

RUN mkdir -p /test && chown wc:wc /test

RUN su - wc -c "source /home/wc/.virtualenvs/witcher/bin/activate && pip install ply "

COPY php8 /phpsrc 

RUN cd /phpsrc && ./buildconf --force

RUN cd /phpsrc &&         \
        ./configure       \
#		--with-config-file-path="$PHP_INI_DIR" \
#		--with-config-file-scan-dir="$PHP_INI_DIR/conf.d" \
        --with-apxs2=/usr/bin/apxs \
#		\
		--enable-cgi      \
        --enable-gettext \
		--enable-ftp      \
		--enable-mbstring \
        --enable-exif \
		--with-gd         \
		\
		--with-openssl \
		--with-curl \
		--with-mysql      \
		--with-ssl      \
		--with-mysqli      \
		--with-pdo-mysql  \
		--with-zlib \
          && printf "\033[36m[Witcher] PHP $PHP_VER Configure completed \033[0m\n"

RUN cd /phpsrc \
	&& make clean &&  EXTRA_CFLAGS="-DWITCHER_DEBUG=1" make -j $(nproc) \
	&& printf "\033[36m[Witcher] PHP $PHP_VER Make completed \033[0m\n"

RUN cd /phpsrc && make install \
	&& printf "\033[36m[Witcher] PHP $PHP_VER Install completed \033[0m\n"

######################################### PHP RUN #################################

RUN apt-fast install -y libpng16-16 net-tools ca-certificates fonts-liberation libappindicator3-1 libasound2 \
                        libatk-bridge2.0-0 libatk1.0-0  libc6 libcairo2 libcups2 libdbus-1-3  libexpat1 libfontconfig1 \
                        libgbm1 libgcc1 libglib2.0-0 libgtk-3-0  libnspr4 libnss3 libpango-1.0-0 libpangocairo-1.0-0 \
                        libstdc++6 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 libxdamage1 libxext6 libxfixes3 \
                        libxi6 libxrandr2 libxrender1 libxss1 libxtst6 lsb-release wget xdg-utils \
                        php-xdebug
RUN php -i

ENV APACHE_RUN_DIR=/etc/apache2/
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf
# RUN ln -s /etc/php/7.1/mods-available/mcrypt.ini /etc/php/7.3/mods-available/ && phpenmod mcrypt

RUN sed -i "s/.*bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/my.cnf && \
  sed -i "s/.*bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/mysql.conf.d/mysqld.cnf

# change apache to forking instead of thread
RUN rm -f /etc/apache2/mods-enabled/mpm_event.* \
    && rm -f /etc/apache2/mods-enabled/mpm_prefork.* \
    && ln -s /etc/apache2/mods-available/mpm_prefork.load /etc/apache2/mods-enabled/mpm_prefork.load \
    && ln -s /etc/apache2/mods-available/mpm_prefork.conf /etc/apache2/mods-enabled/mpm_prefork.conf

#RUN wget http://pear.php.net/go-pear.phar --quiet -O /tmp/go-pear.phar
#RUN echo '/usr/bin/php /tmp/go-pear.phar "$@"' > /usr/bin/go-pear && chmod +x /usr/bin/go-pear
#RUN cd /tmp && /usr/bin/go-pear && rm /usr/bin/go-pear
COPY config/supervisord.conf /etc/supervisord.conf
COPY config/php.ini /usr/local/lib/php.ini
COPY config/php.ini /etc/php/8.3/apache2/php.ini
COPY config/php8.conf config/php8.load /etc/apache2/mods-available/

RUN ln -f -s /etc/apache2/mods-available/php8.load /etc/apache2/mods-enabled/ && ln -f -s /etc/apache2/mods-available/php8.conf /etc/apache2/mods-enabled/

#COPY config/php.ini /etc/php/5.5/cli/php.ini

#RUN ln -s /etc/apache2/mods-available/php7.conf /etc/apache2/mods-enabled/php5.conf
#    &&  ln -s /etc/apache2/mods-available/php5.load /etc/apache2/mods-enabled/php5.load

RUN a2enmod rewrite
ENV PHP_UPLOAD_MAX_FILESIZE 200M
ENV PHP_POST_MAX_SIZE 10M
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

#RUN echo alias p='python -m witcher --affinity $(( $(ifconfig |egrep -oh "inet 172[\.0-9]+"|cut -d "." -f4) * 2 ))' >> /home/wc/.bashrc
COPY config/py_aff.alias /root/py_aff.alias
RUN cat /root/py_aff.alias >> /home/wc/.bashrc

#RUN cp /bin/dash /bin/saved_dash && cp /crashing_dash /bin/dash
# there's a problem with building xdebug and the modifid dash, so copy after xdebug

COPY --chown=wc:wc  config/codecov_conversion.py config/enable_cc.php /

USER wc
RUN mkdir /tmp/coverages

USER root
######## WORDPRESS INSTALL ######

WORKDIR /app/
RUN wget https://ko.wordpress.org/latest-ko_KR.zip && unzip latest-ko_KR.zip
RUN mv wordpress/* ./ && rmdir wordpress

######## DASH ######

COPY dash /dash
RUN chmod 777 /dash && cp -rf /dash /bin/dash

####### FUZZER TEST #######

COPY client_test /

CMD /netconf.sh && /usr/bin/supervisord






