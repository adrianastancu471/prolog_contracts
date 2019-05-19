transferlicenta(X,Y,T):-cantransfer(T),licentavalida(X),taravalida(Y).
taravalida(uruguay).
licentavalida(X):- X < 1597667918385.
cantransfer(full).
