<?php

namespace Iapps\PaymentService\Common\TMoneySwitch;

class TMoneySwitchSignature{

	public static function generateInquiryRequest($username, $password, $signed_data, $locator_code){
		return '<SOAPenv:Envelope xmlns:SOAPenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:rem="http://www.bdo.com.ph/RemitAPI">
		<SOAPenv:Header/>
		<SOAPenv:Body>
		<rem:apiStatusRequest>
		         <rem:userName>'. $username .'</rem:userName>
				 <rem:password>'. $password .'</rem:password>
	 			 <rem:signedData>'. $signed_data .'</rem:signedData>
		         <rem:locatorCode>'. $locator_code .'</rem:locatorCode>
		         %s
		</rem:apiStatusRequest>
		</SOAPenv:Body>
		</SOAPenv:Envelope>';
	}

	public static function generateRemitRequest($username, $password, $signed_data, $conduit_code, $locator_code){
		return '<SOAPenv:Envelope xmlns:SOAPenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:rem="http://www.bdo.com.ph/RemitAPI">
		<SOAPenv:Header/>
		<SOAPenv:Body>
		<rem:apiRequest>
		         <rem:userName>'. $username .'</rem:userName>
				 <rem:password>'. $password .'</rem:password>
	 			 <rem:signedData>'. $signed_data .'</rem:signedData>
		         <rem:conduitCode>'. $conduit_code .'</rem:conduitCode>
		         <rem:locatorCode>'. $locator_code .'</rem:locatorCode>
		         %s
		</rem:apiRequest>
		</SOAPenv:Body>
		</SOAPenv:Envelope>';
	}

}