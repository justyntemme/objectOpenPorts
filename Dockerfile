FROM python:3.7-slim
ENV pcIdentity="" \
  pcSecret="" \
  tlUrl=""
ADD main.py .
RUN pip install requests
CMD ["python", "./main.py"]
