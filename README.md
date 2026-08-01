# Bookkeeping — phone app

An offline receipt-scanning ledger. Everything is encrypted and stored only
on your phone. This README covers the one-time setup to get it installed.

## 1. Put it online once (so your phone can install it)

Android needs a secure (https) address the *first* time to install a web
app to your home screen. After that one install, it never needs the
internet again for anything except optional first-time OCR setup (see
below) or actual internet-requiring receipts.

**Free way to do this with GitHub (no coding required):**

1. Go to [github.com](https://github.com) and create a free account if you
   don't have one.
2. Click the **+** in the top right → **New repository**. Name it anything,
   e.g. `my-bookkeeping`. Set it to **Public**. Click **Create repository**.
3. On the new repo page, click **uploading an existing file** (or drag and
   drop). Drag in *every file and folder* from this `bookkeeping-app`
   folder, including the `icons` folder. Click **Commit changes**.
4. Go to the repo's **Settings** tab → **Pages** (left sidebar).
5. Under "Build and deployment", set **Source** to **Deploy from a
   branch**, branch **main**, folder **/(root)**. Click **Save**.
6. Wait about a minute, then refresh the page — it'll show a link like
   `https://yourusername.github.io/my-bookkeeping/`. That's your app's
   address.

## 2. Install it on your phone

1. Open that link in **Chrome** on your Android phone.
2. Tap the **⋮** menu → **Add to Home screen** (Chrome may also prompt you
   automatically with an "Install app" banner).
3. Open it from your home screen from now on, like any other app.

## 3. First run

1. You'll be asked to create a password — this encrypts everything on your
   phone. Write it down somewhere safe (a paper notebook is fine). If it's
   lost, the data cannot be recovered — that's the trade-off of real
   encryption.
2. Tap **Scan** and take a photo of a receipt the first time. This
   downloads the offline text-reading model (a few MB, one-time, needs
   internet). After that, scanning works with **no internet connection at
   all**, forever.
3. Optionally turn on **biometric unlock** in Settings. This uses your
   phone's fingerprint/face unlock as a convenience shortcut. It's
   feature-dependent on your exact phone/Chrome version — if it's not
   supported, the toggle will tell you and your password still works
   exactly the same either way.

## What to expect from the receipt scanning

The camera reads the photo and takes its best guess at the date, amount,
and vendor. It is genuinely a best guess, not a guarantee — check the
numbers on the confirm screen before saving, especially the total. This
matches how commercial receipt-scanning apps work too; fully-automatic
perfect extraction isn't realistic from photographed paper receipts.

## Backups

- **Settings → Export backup** saves one encrypted file. The app will ask
  you, once, to choose a folder — pick or create a folder called
  `Bookkeeping` so every backup lands in the same place. If your phone/
  browser doesn't support that folder picker, it'll download normally and
  tell you to move it into a `Bookkeeping` folder yourself.
- A banner appears in the app if it's been 7+ days since your last backup.
  Note: this is an in-app reminder, shown when you open the app — it is
  **not** a push notification that can wake your phone up on its own. A
  true "buzzes you every Monday even with the app closed" reminder needs a
  server relay, which would break the fully-offline design. The trade-off
  is: open the app regularly, and it'll always tell you if you're overdue.
- Bring that backup file to the USB app to merge it into your master
  ledger (see the USB app's own README).

## Your data, plainly

- Nothing you enter — vendor names, amounts, receipt photos — ever leaves
  your phone unless you explicitly export a backup file yourself.
- The one-time OCR model download and the Google Fonts used for styling
  are the only things that ever touch the internet, and only once each.
- This tool does not know Swedish tax law and isn't a substitute for a
  bookkeeper — it gives you a clean, dated, categorized record; it's worth
  a quick check with an accountant that the categories and VAT handling
  match what your business needs.
