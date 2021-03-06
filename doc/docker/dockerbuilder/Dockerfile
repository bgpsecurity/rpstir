# Version 1.0
# Comment rpstir on centos6.9
FROM docker.io/centos:6.9

# copy needed files
RUN mkdir -p /root/file
COPY * /root/file/

# install bases file
RUN yum -y update && yum install -y -q \
    build-essential \
    vim  \
    unzip  \
    net-tools  \
    git  \
    autoreconf  \
    initscripts \
    gcc \
    patch  \
    telnet  \
    gettext \
    libtool  \
    libevent \
    rsyslog  \
    wget     \
    autoconf \
    automake \
    crontab \

manuall install 

# install netcat
RUN mkdir /root/netcat \
    && cd /root/netcat \
    && wget --inet4-only  https://downloads.sourceforge.net/project/netcat/netcat/0.7.1/netcat-0.7.1.tar.gz?r=http%3A%2F%2Fnetcat.sourceforge.net%2Fdownload.php -O netcat-0.7.1.tar.gz \
    && tar xzvf netcat-0.7.1.tar.gz \
    && cd /root/netcat/netcat-0.7.1 \
    && ./configure \
    && make  \
    && make  install \ 
    && rm -rf /root/netcat 

# install python 2.7
RUN mkdir /root/python \
    && cd /root/python \
    && wget --inet4-only https://www.python.org/ftp/python/2.7.14/Python-2.7.14.tgz \
    && tar zxf Python-2.7.14.tgz \
    && cd /root/python/Python-2.7.14 \
    && ./configure  \
    && make  \
    && make  install \
    && rm -rf /root/python \
    && echo "export PATH=/usr/local/bin:$PATH" >>  /etc/profile 
    
# install cryptlib
RUN mkdir /root/cryptlib \
    && cd /root/cryptlib \
#    && wget  --inet4-only --passive ftp://ftp.franken.de/pub/crypt/cryptlib/cl3431.zip \
    && cp /root/file/cl3431.zip /root/cryptlib/ \
    && unzip -a cl3431.zip -d cryptlib3431 \
    && cd cryptlib3431 \
    && make  shared  \
    && install -o root -g root -m 755 libcl.so.3.4.3 /usr/local/lib \
    && ln -s /usr/local/lib/libcl.so.3.4.3 /usr/local/lib/libcl.so.3.4  \
    && ln -s /usr/local/lib/libcl.so.3.4.3 /usr/local/lib/libcl.so  \
    && install -o root -g root -m 644 cryptlib.h /usr/local/include \
    && rm -rf /root/cryptlib 

# install openssl1.0.2l
RUN mkdir /root/openssl \
    && cd /root/openssl \
    && wget --inet4-only https://www.openssl.org/source/openssl-1.1.1d.tar.gz \
    && tar xzvf openssl-1.1.1d.tar.gz \
    && cd openssl-1.1.1d \
    && ./config  shared enable-rfc3779 \
    && make  depend \
    && make  \
    && make  install \
    && echo "export PATH=/usr/local/ssl/bin:$PATH" >> /etc/profile \
    && source /etc/profile \
    && rm -rf /root/openssl 


# install mysql
RUN mkdir /root/mysql \
    && cd /root/mysql \
    && rm -rf /var/lib/mysql  \
    && wget  --no-verbose --inet4-only https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-community-server-5.7.20-1.el6.x86_64.rpm \
    && wget  --no-verbose --inet4-only https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-community-client-5.7.20-1.el6.x86_64.rpm \
    && wget  --no-verbose --inet4-only https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-community-devel-5.7.20-1.el6.x86_64.rpm \
    && wget  --no-verbose --inet4-only https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-community-common-5.7.20-1.el6.x86_64.rpm \
    && wget  --no-verbose --inet4-only https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-community-libs-5.7.20-1.el6.x86_64.rpm \
    && wget  --no-verbose --inet4-only https://dev.mysql.com/get/Downloads/Connector-ODBC/5.3/mysql-connector-odbc-5.3.9-1.el6.x86_64.rpm \
    && wget  --no-verbose --inet4-only https://dev.mysql.com/get/Downloads/Connector-ODBC/5.3/mysql-connector-odbc-setup-5.3.9-1.el6.x86_64.rpm \
    && yum  localinstall -y -q *.rpm  \ 
    && cp /root/file/mysql* /root/mysql/  \ 
#   && rm -rf /var/lib/mysql \ 
    && cp /etc/my.cnf /root/mysql/my.cnf \
    && echo 'skip-grant-tables' >> /etc/my.cnf \
    && service mysqld start \
    && cd /root/mysql \
    && chmod +x *.sh \
    && ./mysqlinit.sh 
   

# install unixodbc
RUN mkdir /root/unixodbc \
    && cd /root/unixodbc \
    && wget --inet4-only ftp://ftp.unixodbc.org/pub/unixODBC/unixODBC-2.3.4.tar.gz \
    && tar xzvf unixODBC-2.3.4.tar.gz \
    && cd unixODBC-2.3.4 \
    && ./configure  \
    && make  \
    && make  install \ 
    && rm -rf /root/unixodbc \
    && mkdir -p /usr/local/etc/ \
    && cp /root/file/*.ini cd  

# install crontab
RUN  mkdir /root/crontab \
    && cd /root/crontab 
RUN  wget http://www.rpmfind.net/linux/centos/6.10/os/x86_64/Packages/cronie-1.4.4-16.el6_8.2.x86_64.rpm \
    && wget http://www.rpmfind.net/linux/centos/6.10/os/x86_64/Packages/crontabs-1.10-33.el6.noarch.rpm \
    && wget http://www.rpmfind.net/linux/centos/6.10/os/x86_64/Packages/cronie-anacron-1.4.4-16.el6_8.2.x86_64.rpm \
    && rpm -ivh cronie-1.4.4-16.el6_8.2.x86_64.rpm --nodeps \
    && rpm -ivh crontabs-1.10-33.el6.noarch.rpm \
    && rpm -ivh cronie-anacron-1.4.4-16.el6_8.2.x86_64.rpm \
    && rm -rf /root/crontab 
    
# install rpstir
RUN cp /root/file/rpstir.test.conf /root/.rpstir.test.conf \
    && mkdir -p /root/rpki /root/rpki/rpstir /root/rpki/rpstir/bin /root/rpki/rpstir/src /usr/local/etc/rpstir /usr/local/var/cache/rpstir  /usr/local/var/lib/rpstir   /usr/local/var/log/rpstir \
    && cp /root/file/rpstir.conf /root/rpki/rpstir/src  \
    && cd /root/rpki/rpstir/src \
    && git clone https://github.com/bgpsecurity/rpstir.git \
    && cd ./rpstir \
    && ./autogen.sh \
    && ./configure -q \
    && make  \
    && mkdir -p /usr/local/var/cache/rpstir-tmp \
    && make install \
    && cp /root/rpki/rpstir/src/rpstir.conf /usr/local/etc/rpstir/rpstir.conf  \
    && cd /root/rpki/rpstir/src/rpstir/doc/docker/dockerbuilder \
    && chmod +x *.sh \
    && crontab crontab_rpstir.conf

# init rpstir
RUN cd /root/ \
    && mkdir -p  /root/rpki/rpstir/bin \
    && ln -s /usr/local/bin/rpstir-initialize  /root/rpki/rpstir/bin/rpstir-initialize \
    && ln -s /usr/local/bin/rpstir-query  /root/rpki/rpstir/bin/rpstir-query \
    && ln -s /usr/local/bin/rpstir-results  /root/rpki/rpstir/bin/rpstir-results \
	  && ln -s /usr/local/bin/rpstir-rpki-rtr-update  /root/rpki/rpstir/bin/rpstir-rpki-rtr-update \
	  && ln -s /usr/local/libexec/rpstir/rpki-rtr-daemon /root/rpki/rpstir/bin/rpki-rtr-daemon \
	  && ln -s /usr/local/bin/rpstir-synchronize  /root/rpki/rpstir/bin/rpstir-synchronize \
	  && ln -s /usr/local/var/cache/rpstir /root/rpki/rpstir/cache \
	  && ln -s /usr/local/var/cache/rpstir-tmp /root/rpki/rpstir/cache-valid \
	  && ln -s /usr/local/var/log/rpstir /root/rpki/rpstir/log \
	  && cp /root/rpki/rpstir/src/rpstir/doc/docker/dockerbuilder/crontab_rpstir.sh /root/rpki/rpstir/bin/ \
	  && cd /root/rpki/rpstir/bin/ \
	  && chmod +x * \
	  && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
	  && echo "Asia/shanghai" > /etc/timezone 

# rpstir initialize and create db table	  
#RUN service mysqld restart \
#	  && cd /root/rpki/rpstir/bin/ \
#	  && ./rpstir-initialize -f \
#	  && cd /root/mysql \
#	  && ./mysql-table.sh \
RUN	cp /root/mysql/my.cnf  /etc/my.cnf \
    && echo "max_prepared_stmt_count=1048576" >> /etc/my.cnf  \
    && echo "innodb_flush_log_at_trx_commit=2" >> /etc/my.cnf
#    && rm -rf /root/mysql 
	   

# clean all rmp
RUN  yum clean all \ 
    && cd /root/file \
    && chmod +x *.sh
#    && rm -rf /root/file 


# start 
#CMD /bin/bash
#ENTRYPOINT service mysqld restart  && /bin/bash 
ENTRYPOINT ["/root/file/start_service.sh"]  
#CMD ["/bin/bash"] 

    


