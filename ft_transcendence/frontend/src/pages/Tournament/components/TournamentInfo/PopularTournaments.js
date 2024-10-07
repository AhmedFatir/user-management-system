import './popularTournaments.css'
import hell from '../../../Game/Game-assets/hell.png'
import { useTranslation } from 'react-i18next'


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

function PopularTournaments({tounament}) {
    const { t } = useTranslation();

    return (
        <div className="PopularTournamentsItemConatiner">
            <div 
            className="PopularTournamentsItem" 
            style={{ backgroundImage: `url(${hell})` }}
            >
                <h3 className="tournament-name">{tounament.name}</h3>
            </div>
            <div className='tounametInfo'>
                <div className="tournament-content">
                    <h4>{t('Winner')}</h4>
                    <div className='WinerImageName'>
                        <img src={`${BACKEND_URL}/media/avatars/2.png`}/>
                        <div className='tournamentWinerNameXP'>
                            <p className="tournament-winner">{tounament.winner}</p>
                            <p>+2000 xp</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default PopularTournaments
