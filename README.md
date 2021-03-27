# Twofish API

## Deployment

Procefile:

```
web: gunicorn -k uvicorn.workers.UvicornWorker app:app
```

Shell commands:

```sh
heroku login
heroku apps:create twofishtech
heroku config:set WEB_CONCURRENCY=3

git clone https://github.com/benfenison/twofish
heroku git:remote -a twofishtech
git push heroku master
```
