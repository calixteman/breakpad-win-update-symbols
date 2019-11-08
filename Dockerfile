FROM python:slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget git \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -d /home/user -s /bin/bash -m user
WORKDIR /home/user
RUN mkdir dump_syms
RUN wget https://bootstrap.pypa.io/get-pip.py \
    && python get-pip.py \
    && wget -qO- https://github.com/mozilla/dump_syms/releases/latest/download/dump_syms-linux-x86_64.tar.gz | tar xvz -C dump_syms

ADD requirements.txt /home/user/
RUN pip install --upgrade -r requirements.txt

RUN apt-get remove -y wget && rm get-pip.py && python -m pip uninstall pip -y

ENV DUMP_SYMS_PATH /home/user/dump_syms/dump_syms-linux-x86_64/dump_syms

# Uncomment next line and comment the next next for local test
#ADD . /home/user
ADD start.sh /home/user/

RUN chown -R user.user /home/user
USER user
