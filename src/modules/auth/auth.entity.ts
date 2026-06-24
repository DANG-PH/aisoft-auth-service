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

  @Column({ nullable: true })
  password: string;

  @CreateDateColumn()
  createdAt: Date;
}
