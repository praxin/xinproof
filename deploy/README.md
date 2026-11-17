# Running Xinproof in your own cloud account

Xinproof runs where your backups already are. Nothing is sent to us: your
backups are downloaded into a machine you control, restored in throwaway Docker
containers with no network access, checked, and deleted. What comes out is a
signed receipt per backup (sizes, hashes, row counts, check results; never row
data) and a pass/fail exit code.

Setup takes about 30 minutes:

1. **Give Xinproof read-only access** to the bucket or container that holds the
   backups. The commands are below: one keyless identity per cloud, scoped to
   that one bucket, allowed to list and read and nothing else.
2. **Schedule it.** Choose one:
   - **GitHub Actions** (easiest, no servers): copy
     [`github-actions/xinproof-nightly.yml`](github-actions/xinproof-nightly.yml)
     into a private repo you own and set the variables it names.
   - **Any Linux machine with Docker** (a VM in your VPC, an on-prem box): run the
     container from cron. See [Docker on a schedule](#docker-on-a-schedule).
3. **Keep a signing key.** Run `xinproof key` once and keep
   `~/.xinproof/keys/ed25519.key` secret. Give the public key
   (`ed25519.pub`) to whoever audits you; they check any receipt with
   `xinproof receipt verify --pubkey ed25519.pub receipt-000001.json`.

What the runner needs: Docker, outbound HTTPS to your storage and to Docker Hub
(for the `postgres` and `mysql` images), and disk for the largest backup about
three times over (download, restore, database files). A GitHub-hosted runner
has about 14 GB free; for larger backups use a self-hosted runner or the Docker
option.

Replace the placeholders in the commands: `ORG/REPO` is the GitHub repo that runs
the workflow, `BUCKET` / `PREFIX` is where the backups are.

## AWS S3

Xinproof needs `s3:ListBucket` and `s3:GetObject`, nothing else.

```bash
# Once per AWS account: trust GitHub's OIDC issuer (skip if it already exists).
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com

ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
cat > trust.json <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"Federated":"arn:aws:iam::${ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"},
 "Action":"sts:AssumeRoleWithWebIdentity",
 "Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com",
   "token.actions.githubusercontent.com:sub":"repo:ORG/REPO:ref:refs/heads/main"}}}]}
EOF
cat > read.json <<'EOF'
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::BUCKET",
  "Condition":{"StringLike":{"s3:prefix":["PREFIX*"]}}},
 {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::BUCKET/PREFIX*"}]}
EOF
aws iam create-role --role-name xinproof-readonly --assume-role-policy-document file://trust.json
aws iam put-role-policy --role-name xinproof-readonly --policy-name read-backups --policy-document file://read.json
```

If the bucket uses SSE-KMS with a customer key, also allow `kms:Decrypt` on that key.

Workflow variables: `XINPROOF_AWS_ROLE_ARN` = `arn:aws:iam::<account>:role/xinproof-readonly`,
`XINPROOF_AWS_REGION` = the bucket's region, `XINPROOF_AWS_LOCATION` = `s3://BUCKET/PREFIX`.

## Azure Blob Storage

Xinproof needs **Storage Blob Data Reader** on the container.

```bash
APP=$(az ad app create --display-name xinproof-readonly --query appId -o tsv)
az ad sp create --id "$APP"
az ad app federated-credential create --id "$APP" --parameters '{
  "name": "github-main", "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:ORG/REPO:ref:refs/heads/main", "audiences": ["api://AzureADTokenExchange"]}'

SCOPE=$(az storage account show -n ACCOUNT --query id -o tsv)/blobServices/default/containers/CONTAINER
az role assignment create --assignee "$APP" --role "Storage Blob Data Reader" --scope "$SCOPE"
```

Workflow variables: `XINPROOF_AZURE_CLIENT_ID` = `$APP`, `XINPROOF_AZURE_TENANT_ID`,
`XINPROOF_AZURE_SUBSCRIPTION_ID`, `XINPROOF_AZURE_LOCATION` = `azblob://ACCOUNT/CONTAINER/PREFIX`.

If sign-in fails with `AADSTS700213` (no matching federated identity), your
organization uses GitHub's immutable subject format. The job log of the failed
`azure/login` step shows the subject GitHub sent, such as
`repo:org@123/repo@456:ref:refs/heads/main`; put exactly that in the federated
credential.

## Google Cloud Storage

Xinproof needs **Storage Object Viewer** on the bucket.

```bash
PROJECT=$(gcloud config get-value project)
NUM=$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')
gcloud iam workload-identity-pools create github --location=global
gcloud iam workload-identity-pools providers create-oidc github --location=global \
  --workload-identity-pool=github --issuer-uri=https://token.actions.githubusercontent.com \
  --attribute-mapping=google.subject=assertion.sub,attribute.repository=assertion.repository \
  --attribute-condition="assertion.repository == 'ORG/REPO' && assertion.ref == 'refs/heads/main'"
gcloud iam service-accounts create xinproof-readonly
SA=xinproof-readonly@$PROJECT.iam.gserviceaccount.com
gcloud storage buckets add-iam-policy-binding gs://BUCKET --member="serviceAccount:$SA" --role=roles/storage.objectViewer
gcloud iam service-accounts add-iam-policy-binding "$SA" --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/$NUM/locations/global/workloadIdentityPools/github/attribute.repository/ORG/REPO"
```

Workflow variables: `XINPROOF_GCP_WIF_PROVIDER` =
`projects/<NUM>/locations/global/workloadIdentityPools/github/providers/github`,
`XINPROOF_GCP_SERVICE_ACCOUNT` = `$SA`, `XINPROOF_GCP_LOCATION` = `gs://BUCKET/PREFIX`.

## Cloudflare R2 and other S3-compatible storage

These have no keyless sign-in from GitHub. Create a read-only API token scoped
to the one bucket (R2: *Object Read only*), store its key pair as repository
secrets, and add a step like:

```yaml
      - name: Verify R2 backups
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.R2_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.R2_SECRET_ACCESS_KEY }}
        run: xinproof verify r2://BUCKET/PREFIX --r2-account-id ${{ vars.R2_ACCOUNT_ID }} $ARGS --output reports/r2.xml --receipts receipts/r2
```

For MinIO, Backblaze B2 or Wasabi use `s3://BUCKET/PREFIX --endpoint https://…`.

## Docker on a schedule

On a machine that already has read access to the storage (an instance role, a
managed identity, or credentials in its environment):

```bash
# /etc/cron.d/xinproof: every night at 02:30
30 2 * * * root docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /var/lib/xinproof:/root/.xinproof -v /var/lib/xinproof/receipts:/work/receipts \
  ghcr.io/praxin/xinproof:0.1.0 verify s3://BUCKET/PREFIX --newest 3 \
  >> /var/log/xinproof.log 2>&1 || logger -t xinproof "backup verification failed"
```

The container starts the restore sandboxes as siblings through the Docker
socket, so it needs access to it. Receipts land in `/var/lib/xinproof/receipts`
and keep one hash chain across runs. To also get Azure or Google credentials
from the host, pass them through with `-e` (or mount `~/.azure` / the
application-default credentials file read-only).

## What to check after the first run

- The job finished and each backup shows PASS, or a FAIL with a reason you can act on.
- `xinproof receipt verify --pubkey ed25519.pub receipts/*/receipt-*.json` says every receipt is valid.
- The receipts contain no table data: open one; it lists checks, counts and hashes only.
