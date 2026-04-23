# Lince

I made Lince out of boredom. It’s just a basic memory scanner—you find a value in a game or program and change it. Layout’s pretty standard: scanner on the right, results on the left, and a list at the bottom to keep track of things.

## How to actually get it running

I wrote this inside a Fedora Distrobox, so if you're using that, here's how to set it up.

### 1. Create your box  
If you haven't created your box yet:
```bash
distrobox create Name-Of-Choice
```

### 2. open your box  
If you haven't opened your box yet:
```bash
distrobox enter Name-Of-Choice
```

### 3. Grab the stuff it needs  
You'll need a compiler and some graphics libraries for the UI:
```bash
sudo dnf install -y make gcc-c++ glfw-devel mesa-libGL-devel libX11-devel libXrandr-devel libXinerama-devel libXcursor-devel libXi-devel
```

### 4. Build it  
Go into the folder where your files are and run:
```bash
make
```

### 5. Run it  
It needs root since it messes with other programs' memory:
```bash
sudo ./Lince
```

## Some stuff to know

It’s not super polished or anything fancy, but it works fine for basic stuff.

You do need sudo to run it:
```bash
sudo ./Lince
```

If the build fails and complains about a missing file, try:
```bash
dnf provides */name-of-file.h
```
