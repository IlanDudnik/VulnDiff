# VulnDiff

## Description
VulnDiff - An IDAPython script that helps you audit diff's between unpatched and patched versions of a binary.


![VulnDiff animated gif](/rsrc/demo.gif?raw=true)

This Script will display a list of all diffed functions as a result from a bindiff file and will check if any 
of them contain one of the target functions.
The output is supposed to be searched, sorted and filtered interactively using IDA's built-in methods.

You can track your progress by marking a "checked" function after you finished reversing it or "interesting"
if you think you should return to it later or share with another researcher by giving him your db file.

## How to use

Just make sure to write the name of the bindiff database and adjust the similarity boundaries, 
press `right-click->save` in order to save to the db your markings.
