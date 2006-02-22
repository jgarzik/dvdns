create table labels (
	name		text primary key,
	id		integer unique
);

create index labels_idx1
on labels (id);

create table rrs (
	name		text,
	suffix		integer,
	type		integer,
	class		integer,
	ttl		integer,
	rdata		blob
);

create index rrs_idx1
on rrs (name, suffix);

