FROM python:slim

RUN useradd -d /home/user -s /bin/bash -m user
WORKDIR /home/user
RUN mkdir dump_syms
ADD requirements.txt .

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget git \
    && wget -qO- https://bootstrap.pypa.io/get-pip.py | python \
    && pip install --disable-pip-version-check --quiet --no-cache-dir -r requirements.txt \
    && wget -qO- https://github.com/mozilla/dump_syms/releases/latest/download/dump_syms-linux-x86_64.tar.gz | tar xvz -C dump_syms \
    && apt-get remove -y wget \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip uninstall pip -y

ENV DUMP_SYMS_PATH /home/user/dump_syms/dump_syms-linux-x86_64/dump_syms

# Uncomment next line and comment the next next for local test
#ADD . /home/user
ADD start.sh /home/user/

RUN chown -R user.user /home/user
USER user
