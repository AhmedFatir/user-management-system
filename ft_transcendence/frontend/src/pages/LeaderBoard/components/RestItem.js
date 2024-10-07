import React from 'react'
import './restItem.css'

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

function RestItem({players, index}) {
    const ifOdd = index % 2 ? true : false;

    let winPer = Math.floor((players.games_won / players.games_played) * 100);
    if (players.games_played === 0)
        winPer = 0

    return (
        <div className={ifOdd ? 'listPlayerContainer' : 'listPlayerContainer Odd'}   style={{ animationDelay: `${index * 0.1}s` }} >
            <div className='number'>
                <p>{index}</p>
            </div>
            <div className='listPlayerInfo'>
                <div className='PlayerImageName'>
                    <div className='playerImage'>
                        <img src={`${BACKEND_URL}${players.avatar}`}/>
                    </div>
                    <div className='PlayerName'>
                        <p>{players.username}</p>
                    </div>
                </div>
                
                <div className='PlayerTotal'>
                    <p>{players.games_played}</p>
                </div>
                <div className='PlayerWin'>
                    <p>{players.games_won}%</p>
                </div>
                <div className='PlayerLoss'>
                    <p>{winPer}%</p>
                </div>
                <div className='PlayerRank'>
                    <p>{players.rank}</p>
                </div>
    
            </div>
        </div>
    )
}

export default RestItem