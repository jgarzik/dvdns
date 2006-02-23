create table labels (
	name		text primary key,
	id		integer unique
);

create table rrs (
	domain		integer,
	type		integer,
	class		integer,
	ttl		integer,
	rdata		blob
);

create index rrs_idx1
on rrs (domain);

