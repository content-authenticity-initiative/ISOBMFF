/*******************************************************************************
 * The MIT License (MIT)
 * 
 * Copyright (c) 2017 DigiDNA - www.digidna.net
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 ******************************************************************************/

/*!
 * @file        main.cpp
 * @copyright   (c) 2017, DigiDNA - www.digidna.net
 * @author      Jean-David Gadina - www.digidna.net
 */

#include <ISOBMFF.hpp>
#include <iostream>
#include <fstream>
#include <cstring>
#include <jsoncons/json.hpp>

//----------------------------------
// Adding support for JUMBF
//----------------------------------

class jumdBox: public ISOBMFF::Box
{
	public:
		
		jumdBox( void ): Box( "jumd" )
		{}
		
		void ReadData( ISOBMFF::Parser & /*parser*/, ISOBMFF::BinaryStream & stream )
		{
			for (int i=0; i<16; i++)
				 uuid[i] = stream.ReadUInt8();

			toggles = stream.ReadUInt8();
			hasSig = ( toggles == 0x0B );	// has signature (SHA-256)

			label = stream.ReadNULLTerminatedString();
			
			/*
				box_id: Option<u32>,          user assigned value (OPTIONAL)
				signature: Option<[u8; 32]>,  SHA-256 hash of the payload (OPTIONAL)
			*/
			if ( stream.HasBytesAvailable() ) {
				if ( hasSig ) {
					for (int i=0; i<32; i++)
						 shaSig[i] = stream.ReadUInt8();
				}
			}
		}

		std::string ToHexString( uint8_t const *u, size_t uSize ) const
		{
			std::stringstream ss;
			
			for ( size_t i=0; i<uSize; i++ ) {
				ss << "0x"
				   << std::hex
				   << std::uppercase
				   << std::setfill( '0' )
				   << std::setw( 2 )
				   << static_cast< uint32_t >( u[i] );
			}
			
			return ss.str();
		}

		std::vector< std::pair< std::string, std::string > > GetDisplayableProperties( void ) const
		{
			std::vector< std::pair< std::string, std::string > > props;

			char bt[4];
			snprintf(bt, sizeof(bt), "%c%c%c%c", (char)uuid[0], (char)uuid[1], (char)uuid[2], (char)uuid[3]);
			props.push_back( { "Box Type",            bt} );
			props.push_back( { "Label",               label } );
			props.push_back( { "Toggles",             ISOBMFF::Utils::ToHexString(toggles) } );
			if ( hasSig ) {
				props.push_back( { "Signature",       ToHexString(shaSig, 32) } );
			}

			return props;
		}
	
private:
	uint8_t 	uuid[16];
	uint8_t 	toggles;
	std::string label;
	bool		hasSig;
	uint8_t 	shaSig[32];
};

class jsonBox : public ISOBMFF::Box
{
public:
	jsonBox( void ): Box( "json" )
	{}
	
	void ReadData( ISOBMFF::Parser & /*parser*/, ISOBMFF::BinaryStream & stream )
	{
		std::vector< uint8_t > data( stream.ReadAllData() );
		jsonData.assign( data.begin(), data.end() );
	}
	
	std::vector< std::pair< std::string, std::string > > GetDisplayableProperties( void ) const
	{
		std::vector< std::pair< std::string, std::string > > props;

		// let's see what happens if we try to read in and then pretty print the JSON
		jsoncons::json js = jsoncons::json::parse(jsonData);
		std::stringstream ss;
		ss << jsoncons::pretty_print(js);
		props.push_back( { "Data", ss.str() } );
	
		return props;
	}

private:
	std::string	jsonData;
};

static void RegisterJUMBFBoxes( ISOBMFF::Parser& inParser)
{
	inParser.RegisterContainerBox( "jumb" );
	
	inParser.RegisterBox( "jumd", [ = ]( void ) -> std::shared_ptr< jumdBox > { return std::make_shared< jumdBox >(); } );
	inParser.RegisterBox( "json", [ = ]( void ) -> std::shared_ptr< jsonBox > { return std::make_shared< jsonBox >(); } );
}



//----------------------------------
int main( int argc, const char * argv[] )
{
    ISOBMFF::Parser parser;
    std::string     path;
    int             i;
    std::ifstream   stream;
    
    if( argc < 2 )
    {
        std::cerr << "No input file provided" << std::endl;

        #if defined( _WIN32 ) && defined( _DEBUG )
        getchar();
        #endif
        
        return EXIT_FAILURE;
    }
    
    for( i = 1; i < argc; i++ )
    {
        path   = argv[ i ];
        stream = std::ifstream( path );
        
        if( path.length() == 0 || stream.good() == false )
        {
            std::cerr << "Input file does not exist: '" << path << "'" << std::endl;

            #if defined( _WIN32 ) && defined( _DEBUG )
            getchar();
            #endif
            
            return EXIT_FAILURE;
        }
        
        stream.close();
        
        try
        {
            parser.AddOption( ISOBMFF::Parser::Options::SkipMDATData );

			// add JUMBF support
			RegisterJUMBFBoxes(parser);

			parser.Parse( path );
        }
        catch( const std::runtime_error & e )
        {
            std::cerr << e.what() << std::endl;

            #if defined( _WIN32 ) && defined( _DEBUG )
            getchar();
            #endif
            
            return EXIT_FAILURE;
        }
        
        std::cout << *( parser.GetFile() ) << std::endl << std::endl;
    }

    #if defined( _WIN32 ) && defined( _DEBUG )
    getchar();
    #endif
    
    return EXIT_SUCCESS;
}
