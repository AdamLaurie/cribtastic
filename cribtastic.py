#! /usr/bin/env python

#  cribtastic.py - gui for playing with crypto cribs
# 
#  Adam Laurie <adam@aperturelabs.com>
#  http://www.aperturelabs.com
# 
#  This code is copyright (c) Aperture Labs Ltd., 2013, All rights reserved.
#
#    This code is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This code is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#

import sys
import copy
from Tkinter import *
import Tkinter

# colours
# light grey = #d9d9d9

class AutoScrollbar(Scrollbar):
    # a scrollbar that hides itself if it's not needed.  only
    # works if you use the grid geometry manager.
    def set(self, lo, hi):
        if float(lo) <= 0.0 and float(hi) >= 1.0:
            # grid_remove is currently missing from Tkinter!
            self.tk.call("grid", "remove", self)
        else:
            self.grid()
        Scrollbar.set(self, lo, hi)
    def pack(self, **kw):
        raise TclError, "cannot use pack with this widget"
    def place(self, **kw):
        raise TclError, "cannot use place with this widget"

def readable(data):
	out= ''
	for x in data:
		if x >= ' ' and x <= '~':
			out += x
		else:
			out += '~'
	return out

# OTP re-use adversary
# if an ASCII character was XOR'd with a space it will be a case-swapped ASCII character
def isxorspace(c):
	if (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '\0':
		return True
	return False

def sxor(s1, s2):
	out= ''
	for x in range(len(s1)):
		out += chr(ord(s1[x]) ^ ord(s2[x]))
	return out

def reset_key(args= None):
	for x in range(len(Key)):
		if not lock_key_var[x].get():
			Key[x]= OriginalKey[x]
			update_key(x)
	update_all()

def update_key(x):
	text_key[x].delete(0,Tkinter.END)
	text_key[x].insert(0, readable(Key[x]))
	hex_key[x].delete(0,Tkinter.END)
	hex_key[x].insert(0, '%02X' % ord(Key[x]))
	update_colour(x)

def print_plaintexts():
	print
	print 'key:'
	for x in range(len(Key)):
		print '%02X' % ord(Key[x]),
	print
	print
	print 'plaintexts:'
	for y in range(len(CipherText)):
		out= ''
		for x in range(len(CipherText[y])):
			if ord(Key[x]):
				out += readable(sxor(CipherText[y][x],Key[x]))
			else:
				out += '_'
		print out

# set background colour for all fields
def update_colour(x):
	if ord(Key[x]):
		hex_key[x].config(bg="green")
		text_key[x].config(bg="green")
	else:
		hex_key[x].config(bg="red")
		text_key[x].config(bg="red")
	for y in range(len(CipherText)):
		try:
			hex_ciph[y][x].config(bg="white")
			if ord(Key[x]):
				if lock_key_var[x].get():
					text_pt[y][x].config(bg="lightblue")
				else:
					text_pt[y][x].config(bg="green")
			else:
				text_pt[y][x].config(bg="white")
		except:
			pass

def update_hex_cipher(x,y):
	hex_ciph[x][y].delete(0,Tkinter.END)
	hex_ciph[x][y].insert(0, '%02X' % ord(CipherText[x][y]) )

def update_plaintext(x,y):
	text_pt[x][y].delete(0,Tkinter.END)
	# only display what we can decode
	if Key[y] != '\0':
		text_pt[x][y].insert(0, readable(chr(ord(CipherText[x][y]) ^ ord(Key[y]))))
		if lock_key_var[y].get():
			text_pt[x][y].config(bg="lightblue")
		else:
			text_pt[x][y].config(bg="green")
	else:
		text_pt[x][y].insert(0, '_')

def update_all():
	for x in range(len(Key)):
		update_key(x)
	for x in range(len(CipherText)):
		for y in range(len(CipherText[x])):
			update_plaintext(x,y)

# attacks

def attack_otp(args=None):
	global Key

	reset_key()
	ciphers= copy.copy(CipherText)
	# take out ciphers we've de-selected
	for x in range(len(ciphers)):
		if not hex_ciph_include_var[x].get():
			ciphers.remove(ciphers[x])
	Key= otp_crack(ciphers)
	update_all()


# auto crack re-used one time pad by spotting where messages were XOR'd with a space
def otp_crack(candidates):
	global Key
	# we will process the entire list once for each ciphertext, rotating the list each time so each message gets to be 'master'
	newkey= copy.copy(Key)
	for r in range(len(candidates)):
		other= 1
		mastermask= [' ' for x in range(len(candidates[0]))]
		# process the first ciphertext against all other candidates
		while other < len(candidates):
			string1= candidates[0]
			string2= candidates[other]
			if len(string1) > len(string2):
				maxlen= len(string2)
			else:
				maxlen= len(string1)
			string1= string1[:maxlen]
			string2= string2[:maxlen]

			# we nullify the key by xoring the two messages together: result is m1 xor m2
			m1m2= sxor(string1,string2)
			# if we get an ASCII letter then one of the strings was an XOR with ' ' (0x20) (or some number or punctuation, so we will get some false positives)
			# if we get an ASCII 0x00 then both of the strings were the same, and *may* have been a ' '
			# (this also results in some false positives, but removes far more false negatives so is overall worth doing)
			mask= []
			for x in m1m2:
				if isxorspace(x):
					mask.append(' ')
				else:
					mask.append('\0')

			# if we see a space in the same place for every message then we know it was in message 1, since that was the only constant
			# and as we are going to repeat this process for every message, we should get every key byte that corresponds to a space in any message
			for x in range(len(mask)):
				if mastermask[x] != mask[x]:
					mastermask[x]= '\0'
			other += 1
		# now we know where the spaces were in string1, an XOR with a space will reveal the key byte
		for x in range(len(string1)):
			if mastermask[x] == ' ':
				if not lock_key_var[x].get():
					newkey[x]= chr(ord(string1[x]) ^ ord(' '))
		# rotate list
		candidates= [candidates.pop()] + candidates

	return newkey
		
### main
# setup
if len(sys.argv) < 3:
	print
	print 'usage: %s <KEY HEX> <CIPHERTEXT HEX> [ <CIPHERTEXT HEX> ... ]' % sys.argv[0]
	print
	exit()

# globals
CipherText= []
for x in sys.argv[2:]:
	CipherText.append(x.decode('hex'))
maxlen= 0
for x in CipherText:
	if len(x) > maxlen:
		maxlen= len(x)
if sys.argv[1] != '':
	Key= sys.argv[1].decode('hex')
else:
	Key= ['\0' for x in range(maxlen)]
OriginalKey= Key

widget_master= Tk()
widget_master.title('Aperture Labs Ltd     cribtastic    info@aperturelabs.com')

hscrollbar = AutoScrollbar(widget_master, orient=HORIZONTAL)
vscrollbar = AutoScrollbar(widget_master)
canvas = Canvas(widget_master, yscrollcommand=vscrollbar.set, xscrollcommand=hscrollbar.set)

vscrollbar.config(command=canvas.yview)
hscrollbar.config(command=canvas.xview)

# make the canvas expandable
widget_master.grid_rowconfigure(0, weight=1)
widget_master.grid_columnconfigure(0, weight=1)

#
# frames
#

frame = Frame(canvas)
frame.rowconfigure(0, weight=1)
frame.columnconfigure(0, weight=1)

frame_commands= LabelFrame(frame, text= " Commands ")
frame_commands.grid(row= 0, column= 0, sticky= E+W)

frame_key= LabelFrame(frame, text= " Key ")
frame_key.grid(row= 1, column= 0, sticky= E+W)

frame_ciph= LabelFrame(frame, text= " Ciphers ")
frame_ciph.grid(row= 2, column= 0, sticky= E+W)

frame_pt= LabelFrame(frame, text= " Plaintexts ")
frame_pt.grid(row= 3, column= 0, sticky= E+W)


# commands frame
button_command_reset= Button(frame_commands, text='RESET Key', command=reset_key)
button_command_reset.grid(padx= 2, pady= 2, row= 0, column= 0, sticky= W)

button_command_print= Button(frame_commands, text='Print Plaintexts', command=print_plaintexts)
button_command_print.grid(padx= 2, pady= 2, row= 0, column= 1, sticky= W)

button_command_otp= Button(frame_commands, text='OTP', command=attack_otp)
button_command_otp.grid(padx= 2, pady= 2, row= 0, column= 2, sticky= W)


# entry field updates

# update a key value from the HEX field
def update_from_hex_key(col= None):
	Key[col]= chr(int(hex_key[col].get(),16))
	lock_key[col].select()
	update_key(col)
	update_all()

# update a key value from the ASCII field
def update_from_text_key(col= None):
	Key[col]= text_key[col].get()
	lock_key[col].select()
	update_key(col)
	update_all()

def update_from_hex_ciph(arg1= None, arg2= None):
	print arg1, arg2
	print 'update!'

# given a correct value for a plaintext byte, get the corresponding key value by XORing
# with the original ciphertext
def update_from_plaintext(row= None, col= None):
	Key[col]= sxor(text_pt[row][col].get(), CipherText[row][col])
	lock_key[col].select()
	update_key(col)
	update_all()

# override backgound colour, or re-set to normal if no colour specified
def highlight_column(event, col= None, colour= None):
	update_colour(col)
	if colour:
		text_key[col].config(bg=colour)
		for x in range(len(CipherText)):
			try:
				hex_ciph[x][col].config(bg=colour)
				text_pt[x][col].config(bg=colour)
			except:
				pass

# key frame
hex_key_label=Label(frame_key, text= " Hex         ")
hex_key_label.grid(padx= 0, pady= 1, row= 0, column= 0)
hex_key= []
for x in range(len(Key)):
	hex_key.append(Entry(frame_key, width= 2))
	hex_key[x].grid(padx= 0, pady= 1, row= 0, column= x + 1)
	hex_key[x].insert(0, '%02X' % ord(Key[x]))
	def hex_key_update_handler(event, x=x):
		return update_from_hex_key(x)
	def highlight_handler(event, x=x, colour="yellow"):
		return highlight_column(event, x, colour)
	def unhighlight_handler(event, x=x, colour=None):
		return highlight_column(event, x, colour)
	hex_key[x].bind('<Return>', hex_key_update_handler)
	hex_key[x].bind('<FocusIn>', highlight_handler)
	hex_key[x].bind('<FocusOut>', unhighlight_handler)
	if ord(Key[x]):
		hex_key[x].config(bg="green")
	else:
		hex_key[x].config(bg="red")

text_key_label=Label(frame_key, text= " ASCII      ")
text_key_label.grid(padx= 0, pady= 1, row= 1, column= 0)
text_key= []
for x in range(len(Key)):
	text_key.append(Entry(frame_key, width= 2))
	text_key[x].grid(padx= 0, pady= 1, row= 1, column= x + 1)
	text_key[x].insert(0, readable(Key[x]))
	def text_key_update_handler(event, x=x):
		return update_from_text_key(x)
	def highlight_handler(event, x=x, colour="yellow"):
		return highlight_column(event, x, colour)
	def unhighlight_handler(event, x=x, colour=None):
		return highlight_column(event, x, colour)
	text_key[x].bind('<Return>', text_key_update_handler)
	text_key[x].bind('<FocusIn>', highlight_handler)
	text_key[x].bind('<FocusOut>', unhighlight_handler)
	if ord(Key[x]):
		text_key[x].config(bg="green")
	else:
		text_key[x].config(bg="red")

lock_key_label=Label(frame_key, text= " Lock       ")
lock_key_label.grid(padx= 0, pady= 1, row= 2, column= 0)
lock_key= []
lock_key_var= []
for x in range(len(Key)):
	lock_key_var.append(Tkinter.IntVar())
	lock_key.append(Checkbutton(frame_key, variable= lock_key_var[x]))
	lock_key[x].grid(padx= 0, pady= 0, row= 2, column= x + 1)
	lock_key[x].deselect()

# cipher frame
hex_ciph= []
hex_ciph_label= []
hex_ciph_include= []
hex_ciph_include_var= []
for x in range(len(CipherText)):
	hex_ciph_label.append(Label(frame_ciph, text= " Hex "))
	hex_ciph_label[x].grid(padx= 2, pady= 1, row= x, column= 0)
	hex_ciph.append([Entry(frame_ciph, width= 2)])
	hex_ciph_include_var.append(Tkinter.IntVar())
	hex_ciph_include.append(Checkbutton(frame_ciph, var= hex_ciph_include_var[x]))
	hex_ciph_include[x].select()
	hex_ciph_include[x].grid(padx= 0, pady= 0, row= x, column= 1)
	for y in range(len(CipherText[x])):
		if y:
			hex_ciph[x].append(Entry(frame_ciph, width= 2))
		hex_ciph[x][y].grid(padx= 2, pady= 0, row= x, column= 2 + y)
		hex_ciph[x][y].bind('<Return>', lambda e: update_from_hex_ciph(x,y))
		update_hex_cipher(x, y)

# plaintext frame
text_pt= []
text_pt_label= []
text_pt_include= []
for x in range(len(CipherText)):
	text_pt_label.append(Label(frame_pt, text= "ASCII"))
	text_pt_label[x].grid(padx= 2, pady= 1, row= x, column= 0)
	text_pt.append([Entry(frame_pt, width= 2)])
	text_pt_include.append(Checkbutton(frame_pt, var= hex_ciph_include_var[x]))
	text_pt_include[x].grid(padx= 0, pady= 0, row= x, column= 1)
	for y in range(len(CipherText[x])):
		if y:
			text_pt[x].append(Entry(frame_pt, width= 2))
		def highlight_handler(event, y=y, colour="yellow"):
			return highlight_column(event, y, colour)
		def unhighlight_handler(event, y=y, colour=None):
			return highlight_column(event, y, colour)
		def pt_handler(event, x=x, y=y):
			return update_from_plaintext(x, y)
		text_pt[x][y].grid(padx= 2, pady= 0, row= x, column= 2 + y)
		text_pt[x][y].bind('<FocusIn>', highlight_handler)
		text_pt[x][y].bind('<FocusOut>', unhighlight_handler)
		text_pt[x][y].bind('<Return>', pt_handler)
		update_plaintext(x,y)

# all set, start the show!

canvas.grid(row=0, column=0, sticky=N+S+E+W)
vscrollbar.grid(row=0, column=1, sticky=N+S)
hscrollbar.grid(row=1, column=0, sticky=E+W)
canvas.create_window(0, 0, anchor=NW, window=frame)
frame.update_idletasks()
canvas.config(scrollregion=canvas.bbox("all"))
widget_master.mainloop()

