import React from 'react'
import './searchItem.css'

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

function SearchItem({result}) {
  // ALSO
  return (
    <div className='SearchItem-container'> 
        <div className="search-image">
            <img src={`${BACKEND_URL}${result.avatar}`}/> 
        </div>
        <div className="search-name">
            <p>{result.username}</p>
        </div>
    </div>
  )
}

export default SearchItem