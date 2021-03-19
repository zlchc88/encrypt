<?php
namespace hcgrzh\haes;
class Haes{
	//密码学方式
	private static $method='aes-256-cbc';
	private static $iv="1234567890abcdef";
	// aes-256-cbc  key=>32 位 aes-128-cbc  key=>16位
	private static $key="1234567890abcdef1234567890abcdef";
	//设置
	private static $setErrorMessage=array();
	//返回错误信息
	public static function getErrorMessage(){
		return implode(",",self::$setErrorMessage);
	}
	//key值设置
	public static function setKey($key){
		self::$key=$key;
	}
	//$iv 16位
	public static function setIV($iv){
		self::$iv=$iv;
		//$cipherlen=openssl_cipher_iv_length('aes-256-cbc');  //获取当前偏移量长度
    	//self::$iv=openssl_random_pseudo_bytes($cipherlen);
	}
	/**
	*$options:
	*0 : 自动对明文进行 padding, 返回的数据经过 base64 编码.
	*1 : OPENSSL_RAW_DATA, 自动对明文进行 padding, 但返回的结果未经过 base64 编码.
	*2 : OPENSSL_ZERO_PADDING, 自动对明文进行 0 填充, 返回的结果经过 base64 编码. 但是, openssl 不推荐 0 填充的方式, 即使选择此项也不会自动进行 padding, 仍需手动 padding.
	*aes-128-cbc key 值为16位   aes-256-cbc key 值为 32位
	*/
	public static function enCBCcryptBase64($data){
		$strEncrypt=openssl_encrypt($data,self::$method,self::$key,OPENSSL_RAW_DATA,self::$iv);
		if(!$strEncrypt){
			$setErrorMessage[]=openssl_error_string();
			return false;
		}
		return base64_encode($strEncrypt);
	}
	public static function deCBCcryptBase64($data){
		$data=base64_decode($data);
		$strDecrypt=openssl_decrypt($data,self::$method,self::$key,OPENSSL_RAW_DATA,self::$iv);
		if(!$strDecrypt){
			$setErrorMessage[]=openssl_error_string();
			return false;
		}
		return $strDecrypt;
	}
	public static function enCBCcryptHex($data){
		$strEncrypt=openssl_encrypt($data,self::$method,self::$key,OPENSSL_RAW_DATA,self::$iv);
		if(!$strEncrypt){
			$setErrorMessage[]=openssl_error_string();
			return false;
		}
		return bin2hex($strEncrypt);
	}
	public static function deCBCcryptHex($data){
		$data=pack('H*',$data);
		$strDecrypt=openssl_decrypt($data,self::$method,self::$key,OPENSSL_RAW_DATA,self::$iv);
		if(!$strDecrypt){
			$setErrorMessage[]=openssl_error_string();
			return false;
		}
		return $strDecrypt;
	}
}
?>