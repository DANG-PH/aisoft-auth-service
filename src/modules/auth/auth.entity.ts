import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from 'typeorm';

@Entity('auth') 
export class AuthEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ nullable: false, unique: true }) // Unique Indexing
  username: string;

  @Column({ nullable: false })
  email : string;

  @Column({ default: 'USER' })
  role: string;

  @Column({ default: 0 })
  tokenVersion: number;

  @Column({ default: 0 })
  type: number;          // 0 = local, 1 = google

  @Column({ nullable: true })
  password: string;

  @CreateDateColumn()
  createdAt: Date;
}
