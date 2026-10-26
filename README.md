# Secure Cloud File Storage & Distributed Storage Management System

College demonstration project using Flask, AES-256-GCM encryption, file segmentation, SHA-256 integrity checks, local simulated distributed storage nodes, optional AWS S3 cloud storage, and optional CloudFront domain configuration.

## Features
- Modern dashboard and file selection
- AES-256-GCM authenticated encryption with a passphrase-derived 256-bit key
- 1 MiB file segmentation across three local simulated nodes
- SHA-256 checksums for each plaintext chunk and the original file
- Decrypt and restore with wrong-key/corruption detection
- Optional upload of encrypted chunks to AWS S3
- Optional S3 retrieval when a local chunk is missing
- Optional CloudFront domain configuration display
- Basic security tests

## Run locally
1. Install Python 3.10 or newer.
2. Open PowerShell in this folder.
3. Run `python -m pip install -r requirements.txt`.
4. Run `python app.py`.
5. Open `http://127.0.0.1:5000`.

## Enable AWS S3 (optional)
1. Create an S3 bucket in your AWS account.
2. Configure credentials using AWS CLI (`aws configure`) or your environment's IAM role. Do not put AWS keys in source code.
3. Set `AWS_REGION`, `AWS_S3_BUCKET`, and optionally `AWS_S3_PREFIX` in your environment. See `.env.example` for names.
4. The app uploads encrypted chunks to S3 using server-side encryption. The local simulated nodes continue to work if AWS is not configured.
5. The IAM identity needs only the relevant `s3:PutObject`, `s3:GetObject`, and `s3:DeleteObject` permissions for the chosen bucket/prefix.

## Enable CloudFront (optional)
Create a CloudFront distribution in AWS with the S3 bucket as its origin, configure access using Origin Access Control (OAC), and set `CLOUDFRONT_DOMAIN` to the distribution domain. This application does not create AWS resources automatically; CloudFront setup must be completed in the AWS console. Do not make the bucket public just to make CloudFront work.

## Security tests
Run `python -m unittest security_test.py`. These are basic demonstration tests, not a professional penetration test or a security certification.

## Important notes
- If AWS settings are absent, the app runs in local demo mode; the dashboard states this.
- CloudFront domain display alone does not mean a distribution is deployed or serving files. Configure the distribution in AWS first.
- Never share your passphrase or AWS credentials. The app does not store the encryption passphrase.
