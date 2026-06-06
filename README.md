# FindMyChild — ReuniteAI v28

## What's New in v28
- 👮 Police Registration & Login (`/police/register`, `/police/login`)
- 📸 Found person photo upload with live preview
- 🖼️ Public Found Gallery (`/found-gallery`) — anyone can browse found persons
- 🤖 Image similarity matching (colour histogram algorithm) with % score in SMS
- 🔒 Police dashboard protected — only verified officers can access `/police`

## Setup

```bash
pip install flask werkzeug Pillow numpy
python app.py
```

## Routes
| Route | Who | Description |
|---|---|---|
| `/` | All | Home page |
| `/report-missing` | Logged-in users | Report a missing person |
| `/report-found` | Logged-in users | Report a found person + upload photo |
| `/found-gallery` | Everyone | Browse all found person photos |
| `/cases` | Everyone | All cases list |
| `/police/register` | Officers | Police officer registration |
| `/police/login` | Officers | Police officer login |
| `/police` | Police only | Police dashboard with found gallery |

## Image Matching Algorithm
Uses colour histogram similarity (Bhattacharyya coefficient):
1. Both photos resized to 64×64
2. 32-bin histogram computed per RGB channel (96 bins total)
3. Normalised and compared → similarity score 0–100%
4. Score shown in SMS alerts and match cards
