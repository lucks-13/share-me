# Share-Me CLI
Hi everyone! this my new short project to test my coding ability without ai, actually im working on a bigger project named prompt sealer which encrypt prompt { .md or .txt } and send it to any ai technically hidding prompt from another user but making sure user use it.

to test my ability of not using ai in any form i build this project, technically i used twice but only for reference and to understand something 

this project uses similar architecture as my bigger project.

i want to build a simple way to send encrypted file via in text formate 

# Work Flow
Any file -> cli converts it into ascii text using url safe encoding. -> share that text as a file or as raw text to another system -> save it as .shareme file -> cli converts back to desired file

note : the file is password protected so if you forgot password then no can decrypt it.

right now it supports {i tried}:
* text file
* binary file
* image file
* video file

it also handles large files based on your own system.


# why i made this project.
i wanted to test my understand and ability on cryptography, luckly i have been learning this topics and concepts for the past 1 month so i am very happy i was able to code without any ai to generate code for me.

# how to run this project.

```
git clone https://github.com/lucks-13/share-me.git
```
```
pythton -m pip install -e .
```
```
share-me --help
```
# Available commands.
1. Encrypt a file.
```
share-me encrypt test.txt -o test.shareme
```
ShareMe will ask for the password and password confirmation.

the encrypted file will be saved on
```
test.shareme
```

2. Decrypt a file.
```
share-me decrypt test.shareme -o 

```