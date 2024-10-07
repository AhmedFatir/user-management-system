import React from 'react'
import './tournamentPlayersItem.css'
import { avatarsUnkown } from '../../../../assets/assets';
const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

function TournamentPlayersItem({players}) {
  const unknownAvatar = avatarsUnkown.img;

  return (
    <div className='TournamentPlayersItem'>
        <div className='firstPlayer'>
            <div className='TournamentPlayers-firstPlayerImage'>
            <img src={players.player1?.avatar ? `${BACKEND_URL}${players.player1.avatar}` : unknownAvatar} alt={players.player1?.username || 'Unknown Player'} />
            </div>
            <div className='TournamentPlayers-firstPlayerName'>
                <p>{players.player1?.username || 'Unknown Player'}</p>

            </div>
        </div>
        <div className='vsLogo'>
            <p>VS</p>
        </div>
        <div className='secondPlayer'>
            <div className='TournamentPlayers-secondPlayerName'>
                <p>{players.player2?.username || 'Unknown Player'}</p>

            </div>
            <div className='TournamentPlayers-secondPlayerImage'>
                <img src={players.player2?.avatar ? `${BACKEND_URL}${players.player2.avatar}` : unknownAvatar} alt={players.player2?.username || 'Unknown Player'} />
            </div>
        </div>
    </div>
  )
}

export default TournamentPlayersItem