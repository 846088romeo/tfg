/*

 AnBx Java Security Library

 Copyright 2011-2024 Paolo Modesti
 Copyright 2018-2024 SCM/SCDT/SCEDT, Teesside University
 Copyright 2016-2018 School of Computer Science, University of Sunderland
 Copyright 2013-2015 School of Computing Science, Newcastle University
 Copyright 2011-2012 DAIS, Universita' Ca' Foscari Venezia
   
 This file is part of AnBx

 AnBx is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 any later version.

 AnBx is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with AnBx. If not, see <http://www.gnu.org/licenses/>.

 */

package anbxj;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.Map;

/**
 * AnBx Agent
 */

public class AnBx_Agent implements java.security.Principal, Serializable {

	 
    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 1L;

    /**
     * The alias associated with the certificate map.
     */
    private String alias;

    /**
     * The map containing certificates associated with different Crypto_KeyStoreType.
     */
    private Map<Crypto_KeyStoreType, Certificate> cert;
    
    /**
     * Constructs an AnBx_Agent with the specified alias.
     *
     * @param alias The alias for the AnBx_Agent.
     */

	public AnBx_Agent(String alias) {
		super();
		this.alias = alias;
	}

	
    /**
     * Constructs an AnBx_Agent with the specified alias and certificates.
     *
     * @param alias The alias for the AnBx_Agent.
     * @param cert  The certificates associated with the AnBx_Agent.
     */
	
	public AnBx_Agent(String alias, Map<Crypto_KeyStoreType, Certificate> cert) {
		super();
		this.alias = alias;
		this.cert = cert;
	}

    /**
     * Constructs an AnBx_Agent with the specified alias and certificates from a Crypto_Wrapper.
     *
     * @param alias The alias for the AnBx_Agent.
     * @param lb    The Crypto_Wrapper from which to retrieve certificates.
     */
	
	public AnBx_Agent(String alias, AnB_Crypto_Wrapper lb) {
		super();
		this.alias = alias;
		this.cert = lb.getRemoteCertificates(alias);

	}
	
    /**
     * Constructs an AnBx_Agent with the specified alias and certificates from a Session.
     *
     * @param alias The alias for the AnBx_Agent.
     * @param lb    The Session from which to retrieve certificates.
     */

	public AnBx_Agent(String alias, AnB_Session lb) {
		super();
		this.alias = alias;
		this.cert = lb.getRemoteCertificates(alias);
	}
	
    /**
     * Checks if the AnBx_Agent has certificates for all specified Crypto_KeyStoreTypes.
     *
     * @return True if the AnBx_Agent is certified for all specified Crypto_KeyStoreTypes, false otherwise.
     */

	public Boolean isCertified() {

		for (Crypto_KeyStoreType kst : Crypto_KeyStoreType.values())
			if (this.cert.get(kst) == null)
				return true;
		return false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (this.equals(obj))
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;

		AnBx_Agent other = (AnBx_Agent) obj;

		for (Crypto_KeyStoreType kst : Crypto_KeyStoreType.values()) {
			if (other.cert.get(kst) == null)
				return false;
			if (!cert.get(kst).equals(other.cert.get(kst)))
				return false;
		}
		return true;
	}
	
    /**
     * Retrieves the certificate associated with the specified Crypto_KeyStoreType.
     *
     * @param kst The Crypto_KeyStoreType for which to retrieve the certificate.
     * @return The certificate associated with the specified Crypto_KeyStoreType.
     */

	public Certificate getCert(Crypto_KeyStoreType kst) {
		return cert.get(kst);
	}

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return alias;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;

		for (Crypto_KeyStoreType kst : Crypto_KeyStoreType.values())
			result = prime * result + ((cert.get(kst) == null) ? 0 : cert.get(kst).hashCode());
		return result;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		String certs = "";
		for (Crypto_KeyStoreType kst : Crypto_KeyStoreType.values())
			certs = certs + "Cert_" + kst.toString() + ": " + cert.get(kst).toString() + "\n";
		return "Alias: " + alias + "\n" + certs;

	}

}
