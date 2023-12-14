# WebTheFuzzer
Docker setting of WebTheFuzzer

# Usage
## Image Build

```bash
docker compose up -d
```

## Install Web App
Install web application in `/app` directory

## Run Crawler
We use [WTF-crawlergo](https://github.com/BoB-WebFuzzing/WTF-crawlergo)

```bash
cd /WTF-Crawler
```

You can edit crawlergo.py to use crawler to your web application

```bash
pip3 install simplejson
make build
python3 crawlergo.py
```

After the crawler ends, run following code:

```
mv request_data.json /fuzzer/json
```

## Run fuzzer
The fuzzer [control tower](https://github.com/BoB-WebFuzzing/fuzzer)
You must modify config.json before running the fuzzer.

```bash
./fuzzer json/config.json json/request_data.json
```

You can view the results in the results folder.
