/*
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen
 
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.
 
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/*
  This module is responsible for managing the known list of DID:SID:name mappings,
  and any signatures that vouch for those mappings.  Similarly, we wish to be able
  to advertise our mapping and any signatures that vouch for us.

  We have the choice of using the rhizome database, some other persistent storage
  or an in-memory structure.  It would be nice to have a fall-back for when we don't 
  have the means to run sqlite.  A small in-memory cache will likely be used, 
  regardless. This initial implementation assumes that we have sqlite and the rhizome
  database instance available.

  So what data do we actually need to tell whether we have verified an identity or not?
  We need a DID:SID[:name] tuple.
  We also need the scope for us to mark a given tuple as verified by ourselves, e.g.,
  using a Diffie-Hellman type exchange between handsets.
  Finally, we want the ability to store any signatures that vouch for the identity of
  a given party.
*/

#include "serval.h"
#include "rhizome.h"

/*
   Look up the verification data for the first matching DID, NAME and/or SID.
   (SIDs really should be unique of course).
   If more than one constraint are provided, then the search results are constrained
   by all provided values.

   Subsequent results can be found by calling dnacache_lookup_next();

   The operation of this call is greatly simplified by the single-threaded operation
   of DNA, meaning that we don't have to be reentrant, so we can retain a database
   cursor and generally make life simple.

   So what kind of results do we need to actually return?
   I guess the initial need is for a simple VERIFIED/NOTVERIFIED result, and
   perhaps make the list of certifying identities available.  Again the 
   single-threaded nature of DNA makes this much simpler than a reentrant version
   would need to be.

   Database schema is:

   "CREATE TABLE IF NOT EXISTS VERIFICATIONS(sid text not null, did text, name text,starttime integer, endtime integer,signature blob);"

*/

/* Cache of verifications.
   This really doesn't need to be too large. */
#define DNA_IDENTITY_CACHE_SIZE 16
int dna_identity_cache_initialisedP=0;
dna_identity_status dna_identity_cache[DNA_IDENTITY_CACHE_SIZE];

dna_identity_status dnacache_lookup(char *did,char *name,char *sid)
{
  /* Mark all slots as unused initially */
  if (!dna_identity_cache_initialisedP) {
    int i;
    for(i=0;i<DNA_IDENTITY_CACHE_SIZE;i++)
      dna_identity_cache[i].initialisedP=0;
    dna_identity_cache_initialisedP=1;
  }

  /* Now prepare the query or see if the identity is already in the cache.
     The cache can be used without database query if SID is specified, since
     that guarantees that only one entry exists.

     Also, if DID/NAME is specified without SID, and the cache entry indicates
     that there are no duplicates for the specified value in the database, then
     the database query can be eshewed.

     Otherwise, the database must be queried.
     
     Negative results are also cached so that database queries can be avoided for
     repeated queries to identies that we do not know about.
  */
}

dna_identity_status dnachache_lookup_next()
{

}

/*
  Record/update the verification status of a DID/SID combination.
  
  If signature is not null, then add this signature to the list of verifications
  for the specified DID/SID/NAME combination.  NAME may be omitted.

  If revokeVerificationP is non-zero, then all existing verifications for the
  specified identity will be revoked.
*/
int dnacache_update_verification(char *did,char *sid,char *name,
				 char *signature,int revokeVerificationP)
{

}

/* Sign a verification record ourselves for the specified identity, by creating 
   and storing signature and adding record to the cache. */
int dnacache_vouch_for_identity(char *did,char *sid,char *name)
{

}
