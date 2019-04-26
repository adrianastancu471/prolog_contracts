from pyswip import Prolog
prolog = Prolog()

#prolog.assertz("father(mai,maiut)")
#prolog.assertz("father(abcd,erfg)")
#list(prolog.query("father(michael,X)"))
#for soln in prolog.query("father(X,Y)"):
#    print(soln["X"], "is the father of", soln["Y"])
# michael is the father of john
# michael is the father of gina"""

prolog_program = "pereche_chei(pk_1,priv_1). \npereche_chei(pk_2,priv_2). \npereche_chei(pk_3,priv_3). "
"""with open("contract.pl","w") as fo:
    fo.write(prolog_program)
#file_contract.write(body)
"""
prolog = Prolog()
prolog.consult("contract.pl")
for soln in prolog.query("pereche_chei(Y,X)"):
    print(soln["X"], "este cheia privata a", soln["Y"])