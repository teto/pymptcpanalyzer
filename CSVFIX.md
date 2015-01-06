# if I use csvfix, I will need the following functions:
# - fix
# - file_split
# - sort 
# - write_multi

# use -o flag to output to a file

# le sort a l'air de bien marcher, dmg qu'il ne presse
# le mptcpstream exporte a l'air d'etre le numero du stream parent ?
# (ou bien en fait certains numéros sont attribués puis 
# ensuite enlevés quand ils sont rattachés a une autre connexion)
# Example
# csvfix sort -rh -f 1:AN <CSV>
# (AN => Ascending Numerically) , -rh (read header)

# csvfix find -f 4 -r 0:0 test.csv (-r => range)

# mptcpstream
# csvfix write_multi

# csvfix write_multi -m 1,2 -rs '\n\n' -smq > test_multi.csv
# 

