create table labels (
	domain		text primary key,
	id		integer unique
);

create index labels_idx1
on labels (id);

create table rrs (
	name		text,
	domain_id	integer,
	type		text(2),
	class		text(2),
	ttl		integer,
	rdata		blob
);

create index rrs_idx1
on rrs (name, domain_id);

