<?php
	/**
	 * @author Pavel Djundik & [ToG] subtlerod
	 *
	 * @link https://xpaw.me
	 * @link https://github.com/xPaw/PHP-Source-Query
	 * @link https://github.com/xPaw/PHP-Source-Query
	 *
	 * @license GNU Lesser General Public License, version 2.1
	 *
	 * @internal
	 */

	namespace xPaw\SourceQuery;

	use xPaw\SourceQuery\Exception\AuthenticationException;
	use xPaw\SourceQuery\Exception\InvalidPacketException;
	use xPaw\SourceQuery\Exception\SocketException;

	/**
	 * Class SquadRcon
	 *
	 * @package xPaw\SourceQuery
	 *
	 * @uses xPaw\SourceQuery\Exception\AuthenticationException
	 * @uses xPaw\SourceQuery\Exception\InvalidPacketException
	 * @uses xPaw\SourceQuery\Exception\SocketException
	 */
	class SquadRcon
	{
		/**
		 * Points to socket class
		 */
		private $Socket;

		/** @var resource */
		private $RconSocket;
		private int $RconRequestId = 0;
		private bool $IsMulti = false;
		private string $CalledCommand = '';

		public function __construct( BaseSocket $Socket )
		{
			$this->Socket = $Socket;
		}

		public function Close( ) : void
		{
			if( $this->RconSocket )
			{
				FClose( $this->RconSocket );

				$this->RconSocket = null;
			}

			$this->RconRequestId = 0;
		}

		public function Open( ) : void
		{
			if( !$this->RconSocket )
			{
				$this->RconSocket = @FSockOpen( $this->Socket->Address, $this->Socket->Port, $ErrNo, $ErrStr, $this->Socket->Timeout );

				if( $ErrNo || !$this->RconSocket )
				{
					throw new SocketException( 'Can\'t connect to RCON server: ' . $ErrStr, SocketException::CONNECTION_FAILED );
				}

				Stream_Set_Timeout( $this->RconSocket, $this->Socket->Timeout );
				Stream_Set_Blocking( $this->RconSocket, true );
			}
		}

		public function Write( int $Header, string $String = '' ) : bool
		{
			// Pack the packet together
			$Command = Pack( 'VV', ++$this->RconRequestId, $Header ) . $String . "\x00\x00";

			// Prepend packet length
			$Command = Pack( 'V', StrLen( $Command ) ) . $Command;
			$Length  = StrLen( $Command );

			return $Length === FWrite( $this->RconSocket, $Command, $Length );
		}

		public function Read( ) : ?Buffer
		{
			$Buffer = new Buffer( );
			$Buffer->Set( FRead( $this->RconSocket, 4 ) );

			if( $Buffer->Remaining( ) < 4 )
			{
				if (!$this->IsMulti)
				{
					throw new InvalidPacketException( 'Rcon read: Failed to read any data from socket', InvalidPacketException::BUFFER_EMPTY );
				} else {
					return null;
				}
			}

			$Encoding = 'ASCII';

			$PacketSize = $Buffer->GetLong( );
			$PacketData = FRead( $this->RconSocket, $PacketSize );

			if ($this->CalledCommand === 'listplayers' || substr( $this->CalledCommand, 0, 8 ) === 'adminban' || substr( $this->CalledCommand, 0, 9 ) === 'adminkick')
			{
				if ( (strlen(rtrim(substr($PacketData, 8), '\0'))) > (strlen(str_replace('\0','',substr($PacketData, 8)))) )
				{
					$PacketData .= FRead( $this->RconSocket, ( $PacketSize - 9 ) );

					$PacketSize += $PacketSize - 9;

					$Encoding = 'UTF-8';
				}
			}

			$Buffer->Set( $PacketData );

			$Data = $Buffer->Get( );

			$Remaining = $PacketSize - StrLen( $Data );

			while( $Remaining > 0 )
			{
				$Data2 = FRead( $this->RconSocket, $Remaining );

				$PacketSize = StrLen( $Data2 );

				if( $PacketSize === 0 )
				{
					throw new InvalidPacketException( 'Read ' . strlen( $Data ) . ' bytes from socket, ' . $Remaining . ' remaining', InvalidPacketException::BUFFER_EMPTY );

					break;
				}

				$Data .= $Data2;
				$Remaining -= $PacketSize;
			}

			if ($Encoding === 'UTF-8')
			{
				$n = 8;
				$CountUTF = 0;
				$BodyEncode = '';
				while (StrLen(substr($Data, 8)) > $n - 8)
				{

					$TwoBytes=bin2hex(substr($Data,($n),2));

					if (($TwoBytes == '0000') || ($TwoBytes == '00'))
					{
						$BodyEncode .= "\0";
					}
					else
					{
						$BodyEncode .= html_entity_decode(("&#x" . substr($TwoBytes,2,2) . substr($TwoBytes,0,2) . ";"), ENT_COMPAT, 'UTF-8');
					}

					if ((substr($TwoBytes,2,2) !== '00') && (substr($TwoBytes,0,2) !== '00'))
					{
						$CountUTF = $CountUTF + 1;
					}
					else
					{
						//
					}

					$n = $n + 2;
				}
				//Replace single quotes html encoding with actual single quotes
				$BodyEncode = str_replace('&#x0027;', '\'', $BodyEncode);
				$Data = substr($Data, 0, 8) . $BodyEncode;
			}

			$Buffer->Set( $Data );

			return $Buffer;
		}

		public function Command( string $Command ) : string
		{
			$this->CalledCommand = strtolower($Command);
			$this->IsMulti = false;

			$this->Write( SourceQuery::SERVERDATA_EXECCOMMAND, $Command );
			$Buffer = $this->Read( );

			$Buffer->GetLong( ); // RequestID

			$Type = $Buffer->GetLong( );

			if( $Type === SourceQuery::SERVERDATA_AUTH_RESPONSE )
			{
				throw new AuthenticationException( 'Bad rcon_password.', AuthenticationException::BAD_PASSWORD );
			}
			else if( $Type !== SourceQuery::SERVERDATA_RESPONSE_VALUE )
			{
				throw new InvalidPacketException( 'Invalid rcon response.', InvalidPacketException::PACKET_HEADER_MISMATCH );
			}

			$Data = $Buffer->Get( );

			// We do this stupid hack to handle split packets
			// See https://developer.valvesoftware.com/wiki/Source_RCON_Protocol#Multiple-packet_Responses
			if( mb_strlen( $Data ) >= 4000 )
			{
				$this->IsMulti = true;

				$this->Write( SourceQuery::SERVERDATA_RESPONSE_VALUE );

				do
				{
					$Buffer = $this->Read( );

					if (!$Buffer) {
						break;
					}

					$Buffer->GetLong( ); // RequestID

					if( $Buffer->GetLong( ) !== SourceQuery::SERVERDATA_RESPONSE_VALUE )
					{
						break;
					}

					$Data2 = $Buffer->Get( );

					if( $Data2 === "\x00\x01\x00\x00\x00\x00" )
					{
						break;
					}

					$Data .= $Data2;

					if(mb_strlen( $Data2 ) < 4000)
					{
						break;
					}
				}
				while( true );
			}

			return rtrim( $Data, '\0' );
		}

		public function Authorize( string $Password ) : void
		{
			$this->Write( SourceQuery::SERVERDATA_AUTH, $Password );
			$Buffer = $this->Read( );

			$RequestID = $Buffer->GetLong( );
			$Type      = $Buffer->GetLong( );

			// If we receive SERVERDATA_RESPONSE_VALUE, then we need to read again
			// More info: https://developer.valvesoftware.com/wiki/Source_RCON_Protocol#Additional_Comments

			if( $Type === SourceQuery::SERVERDATA_RESPONSE_VALUE )
			{
				$Buffer = $this->Read( );

				$RequestID = $Buffer->GetLong( );
				$Type      = $Buffer->GetLong( );
			}

			if( $RequestID === -1 || $Type !== SourceQuery::SERVERDATA_AUTH_RESPONSE )
			{
				throw new AuthenticationException( 'RCON authorization failed.', AuthenticationException::BAD_PASSWORD );
			}
		}
	}
