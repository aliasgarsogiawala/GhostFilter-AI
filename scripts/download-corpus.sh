#!/usr/bin/env bash
# Downloads the SpamAssassin public corpus used to train the classifier.
# The raw corpus is gitignored (~42MB, ~6000 files); only the trained weights
# (lib/ml-weights.json) are committed. Run this before `npm run train-classifier`.
set -euo pipefail

DEST="$(cd "$(dirname "$0")" && pwd)/data/spamassassin"
BASE="https://spamassassin.apache.org/old/publiccorpus"
FILES=(
  "20030228_easy_ham.tar.bz2"
  "20030228_easy_ham_2.tar.bz2"
  "20030228_hard_ham.tar.bz2"
  "20030228_spam.tar.bz2"
  "20050311_spam_2.tar.bz2"
)

mkdir -p "$DEST"
cd "$DEST"
for f in "${FILES[@]}"; do
  echo "Downloading $f..."
  curl -s -O "$BASE/$f"
  tar xjf "$f"
  rm -f "$f"
done
echo "Done. Corpus extracted to $DEST"
