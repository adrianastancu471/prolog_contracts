transferlicenta(X,Y,T):-cantransfer(T),licentavalida(X),taravalida(Y).
taravalida(franta).
taravalida(germania).
taravalida(romania).
licentavalida(X):- X < 1575456185887.
cantransfer(full).
